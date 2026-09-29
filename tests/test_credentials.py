import json
from datetime import timedelta

import boto3
import pytest
from conftest import ALICE, BOB, GRACE, MAYA
from moto import mock_aws

from app import credentials
from app.database import SessionLocal, utcnow
from app.models import AccessRequest
from app.scheduler import prune_cloud_revocations, revoke_expired_grants
from seed_data import AWS_BACKING

ROLE = "aegis-jit-data-lake"


@pytest.fixture()
def aws(monkeypatch):
    monkeypatch.setenv("AEGIS_CREDENTIAL_BROKER", "aws")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AEGIS_AWS_ACCOUNT_ID", "123456789012")  # moto's default account
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        for _, _, role in AWS_BACKING.values():
            iam.create_role(RoleName=role, AssumeRolePolicyDocument="{}", MaxSessionDuration=3600)
        yield iam


@pytest.fixture()
def aws_client(aws, client):
    """Re-seed after the env vars are set so resource ARNs point at the mocked account."""
    from seed_data import seed

    seed(reset=True)
    return client


def _grant(client, headers, text="read s3-data-lake for 2 hours to rebuild the report"):
    body = client.post("/request-access", json={"request_text": text}, headers=headers).json()
    assert body["status"] == "ACTIVE", body
    return body["request_id"]


def _revocations(iam):
    try:
        doc = iam.get_role_policy(RoleName=ROLE, PolicyName=credentials.REVOCATION_POLICY_NAME)["PolicyDocument"]
    except iam.exceptions.NoSuchEntityException:
        return []
    return (json.loads(doc) if isinstance(doc, str) else doc)["Statement"]


@pytest.mark.parametrize(
    "service, action, expected",
    [
        ("s3", "read", {"s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"}),
        ("s3", "write", {"s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:PutObject"}),
        ("dynamodb", "admin", {"dynamodb:*"}),
    ],
)
def test_iam_actions_follow_least_privilege(service, action, expected):
    assert set(credentials.iam_actions(service, action)) == expected


def test_issue_scoped_credentials(aws_client, auth, aws):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice)
    resp = aws_client.post(f"/grants/{grant_id}/credentials", headers=alice)
    assert resp.status_code == 200, resp.text
    assert resp.headers["cache-control"] == "no-store"
    creds = resp.json()
    assert creds["access_key_id"].startswith("ASIA") and creds["session_name"] == f"aegis-{grant_id}-1"
    statement = creds["session_policy"]["Statement"][0]
    assert statement["Resource"] == ["arn:aws:s3:::aegis-data-lake", "arn:aws:s3:::aegis-data-lake/*"]
    assert "s3:PutObject" not in statement["Action"]

    # The credentials work against (mocked) STS and are attributed to the session.
    identity = boto3.client(
        "sts",
        region_name="us-east-1",
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        aws_session_token=creds["session_token"],
    ).get_caller_identity()
    assert identity["Arn"].endswith(f"assumed-role/{ROLE}/aegis-{grant_id}-1")

    logs = aws_client.get("/audit-logs", params={"event": "CREDENTIALS_ISSUED"}, headers=auth(GRACE)).json()
    assert len(logs) == 1 and creds["access_key_id"] in logs[0]["detail"]
    assert creds["secret_access_key"] not in logs[0]["detail"]


def test_only_grantee_receives_credentials(aws_client, auth):
    grant_id = _grant(aws_client, auth(ALICE))
    for other in (BOB, MAYA, GRACE):
        assert aws_client.post(f"/grants/{grant_id}/credentials", headers=auth(other)).status_code == 404


def test_session_never_outlives_grant(aws_client, auth):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice)
    with SessionLocal() as db:
        db.get(AccessRequest, grant_id).expires_at = utcnow() + timedelta(minutes=10)
        db.commit()
    resp = aws_client.post(f"/grants/{grant_id}/credentials", headers=alice)
    assert resp.status_code == 409 and "15 minutes" in resp.json()["detail"]


def test_resources_without_aws_backing(aws_client, auth):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice, "read prod-db for 2 hours to debug")
    assert aws_client.post(f"/grants/{grant_id}/credentials", headers=alice).status_code == 422


def test_broker_disabled(client, auth, monkeypatch):
    monkeypatch.setenv("AEGIS_CREDENTIAL_BROKER", "none")
    alice = auth(ALICE)
    grant_id = _grant(client, alice)
    assert client.post(f"/grants/{grant_id}/credentials", headers=alice).status_code == 501


def test_early_revoke_denies_issued_sessions(aws_client, auth, aws):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice)
    aws_client.post(f"/grants/{grant_id}/credentials", headers=alice)
    aws_client.post(f"/grants/{grant_id}/revoke", json={"reason": "incident closed"}, headers=alice)

    [statement] = _revocations(aws)
    assert statement["Effect"] == "Deny"
    assert statement["Condition"]["StringLike"]["aws:userid"] == f"*:aegis-{grant_id}-1"
    events = [e["event"] for e in aws_client.get("/audit-logs", headers=auth(GRACE)).json()]
    assert events[0] == "CLOUD_SESSIONS_REVOKED"


def test_leaver_denies_issued_sessions(aws_client, auth, aws):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice)
    aws_client.post(f"/grants/{grant_id}/credentials", headers=alice)
    aws_client.patch("/users/1", json={"is_active": False}, headers=auth("iris.novak@aegis.example"))
    assert len(_revocations(aws)) == 1


def test_natural_expiry_needs_no_deny(aws_client, auth, aws):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice)
    aws_client.post(f"/grants/{grant_id}/credentials", headers=alice)
    with SessionLocal() as db:
        db.get(AccessRequest, grant_id).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert revoke_expired_grants() == 1
    assert _revocations(aws) == []


def test_prune_removes_expired_denies(aws_client, auth, aws, monkeypatch):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice)
    aws_client.post(f"/grants/{grant_id}/credentials", headers=alice)
    aws_client.post(f"/grants/{grant_id}/revoke", json={"reason": "done"}, headers=alice)
    assert prune_cloud_revocations() == 0  # sessions could still be alive
    monkeypatch.setenv("AEGIS_AWS_MAX_SESSION_SECONDS", "-5")  # pretend every session has expired
    assert prune_cloud_revocations() == 1
    assert _revocations(aws) == []


def test_cloud_revocation_failure_is_audited(aws_client, auth, monkeypatch):
    alice = auth(ALICE)
    grant_id = _grant(aws_client, alice)
    aws_client.post(f"/grants/{grant_id}/credentials", headers=alice)

    def boom(*_):
        raise RuntimeError("AccessDenied: iam:PutRolePolicy")

    monkeypatch.setattr(credentials, "revoke_sessions", boom)
    resp = aws_client.post(f"/grants/{grant_id}/revoke", json={"reason": "done"}, headers=alice)
    assert resp.json()["status"] == "REVOKED"
    failed = aws_client.get("/audit-logs", params={"event": "CLOUD_REVOCATION_FAILED"}, headers=auth(GRACE)).json()
    assert len(failed) == 1 and "Manual action required" in failed[0]["detail"]
