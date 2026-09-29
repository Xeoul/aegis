"""AWS STS credential broker: turns an ACTIVE grant into real, short-lived AWS credentials.

For a grant on a resource with ``aws_role_arn`` configured, the broker calls
``sts:AssumeRole`` with:

* a **session policy** that allows only the IAM actions matching the granted action on that
  one resource. AWS takes the intersection of the role's policy and the session policy, so the
  credentials are no more powerful than the grant, even if the role is broader.
* a **duration** that never outlives the grant (and never exceeds the role's session limit).
* ``SourceIdentity`` = the user's email and session tags, so CloudTrail attributes every API
  call to the human and the Aegis request.
* ``RoleSessionName`` = ``aegis-<request id>-<user id>``.

STS credentials cannot be recalled once issued. For early revocation the broker adds a Deny
statement to the role's ``AegisRevokedSessions`` inline policy. It matches that grant's
session name through ``aws:userid``, so it blocks sessions already in circulation.
:func:`prune_revocations` removes statements once every session they could match has expired.
"""

import contextlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.database import utcnow
from app.models import AccessRequest, Resource, User

logger = logging.getLogger(__name__)

STS_MIN_SECONDS = 900
REVOCATION_POLICY_NAME = "AegisRevokedSessions"

# IAM actions allowed in the session policy, per AWS service and Aegis action.
_READ = {
    "s3": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
    "dynamodb": [
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable",
    ],
    "secretsmanager": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
    "kms": ["kms:DescribeKey", "kms:Decrypt"],
}
_WRITE = {
    "s3": ["s3:PutObject"],
    "dynamodb": ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:BatchWriteItem"],
    "secretsmanager": ["secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret"],
    "kms": ["kms:Encrypt", "kms:GenerateDataKey"],
}
_DELETE = {
    "s3": ["s3:DeleteObject"],
    "dynamodb": ["dynamodb:DeleteItem"],
    "secretsmanager": ["secretsmanager:DeleteSecret"],
    "kms": ["kms:ScheduleKeyDeletion"],
}
SUPPORTED_SERVICES = set(_READ)


class BrokerError(RuntimeError):
    pass


def iam_actions(service: str, action: str) -> list[str]:
    if service not in SUPPORTED_SERVICES:
        raise BrokerError(f"Unsupported AWS service {service!r}")
    if action == "admin":
        return [f"{service}:*"]
    actions = list(_READ[service])
    if action in ("write", "delete"):
        actions += _WRITE[service]
    if action == "delete":
        actions += _DELETE[service]
    return actions


def session_policy(resource: Resource, action: str) -> dict[str, Any]:
    if not (resource.aws_service and resource.aws_resource_arn):
        raise BrokerError(f"Resource {resource.name} has no AWS service/ARN configured")
    arns = [resource.aws_resource_arn]
    if resource.aws_service == "s3":
        arns.append(f"{resource.aws_resource_arn}/*")  # objects inside the bucket
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AegisJitGrant",
                "Effect": "Allow",
                "Action": iam_actions(resource.aws_service, action),
                "Resource": arns,
            }
        ],
    }


def session_name(grant: AccessRequest) -> str:
    return f"aegis-{grant.id}-{grant.user_id}"


@dataclass
class IssuedCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    role_arn: str
    session_name: str
    session_policy: dict[str, Any]


def enabled() -> bool:
    return os.getenv("AEGIS_CREDENTIAL_BROKER", "none").lower() == "aws"


def _max_session_seconds() -> int:
    return int(os.getenv("AEGIS_AWS_MAX_SESSION_SECONDS", "3600"))


def _client(service: str) -> Any:
    import boto3  # imported lazily so the broker stays optional

    # boto3 honours AWS_ENDPOINT_URL, which points it at LocalStack for local testing.
    return boto3.client(service, region_name=os.getenv("AWS_REGION", "us-east-1"))


def _role_name(role_arn: str) -> str:
    return role_arn.rsplit("/", 1)[-1]


def issue(grant: AccessRequest, resource: Resource, user: User) -> IssuedCredentials:
    if not resource.aws_role_arn:
        raise BrokerError(f"Resource {resource.name} is not backed by an AWS role")
    if grant.expires_at is None:
        raise BrokerError("Grant has no expiry")
    remaining = int((grant.expires_at - utcnow()).total_seconds())
    if remaining < STS_MIN_SECONDS:
        # STS cannot issue sessions shorter than 15 minutes; issuing one would outlive the grant.
        raise BrokerError("Grant ends in under 15 minutes, the shortest session STS can issue")
    duration = min(remaining, _max_session_seconds())
    policy = session_policy(resource, grant.action)
    name = session_name(grant)
    resp = _client("sts").assume_role(
        RoleArn=resource.aws_role_arn,
        RoleSessionName=name,
        DurationSeconds=duration,
        Policy=json.dumps(policy),
        SourceIdentity=user.email,
        Tags=[
            {"Key": "aegis:request-id", "Value": str(grant.id)},
            {"Key": "aegis:action", "Value": grant.action},
        ],
    )
    creds = resp["Credentials"]
    return IssuedCredentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        expiration=creds["Expiration"],
        role_arn=resource.aws_role_arn,
        session_name=name,
        session_policy=policy,
    )


def _load_revocations(iam: Any, role: str) -> list[dict[str, Any]]:
    try:
        doc = iam.get_role_policy(RoleName=role, PolicyName=REVOCATION_POLICY_NAME)["PolicyDocument"]
    except iam.exceptions.NoSuchEntityException:
        return []
    if isinstance(doc, str):
        doc = json.loads(doc)
    return list(doc.get("Statement", []))


def _save_revocations(iam: Any, role: str, statements: list[dict[str, Any]]) -> None:
    if not statements:
        with contextlib.suppress(iam.exceptions.NoSuchEntityException):
            iam.delete_role_policy(RoleName=role, PolicyName=REVOCATION_POLICY_NAME)
        return
    iam.put_role_policy(
        RoleName=role,
        PolicyName=REVOCATION_POLICY_NAME,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def revoke_sessions(grant: AccessRequest, resource: Resource) -> None:
    """Deny every AWS session issued for this grant, including ones already handed out."""
    if not resource.aws_role_arn:
        return
    iam = _client("iam")
    role = _role_name(resource.aws_role_arn)
    now = datetime.now(UTC)
    sid = f"AegisRevoke{grant.id}"
    statements = [s for s in _load_revocations(iam, role) if s.get("Sid") != sid]
    statements.append(
        {
            "Sid": sid,
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringLike": {"aws:userid": f"*:{session_name(grant)}"},
                # Only sessions issued before revocation; also records when it can be pruned.
                "DateLessThan": {"aws:TokenIssueTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
            },
        }
    )
    _save_revocations(iam, role, statements)
    logger.info("Denied AWS sessions for grant %s on %s", grant.id, role)


def prune_revocations(role_arn: str) -> int:
    """Drop Deny statements whose sessions have all expired. Returns how many were removed."""
    iam = _client("iam")
    role = _role_name(role_arn)
    statements = _load_revocations(iam, role)
    horizon = datetime.now(UTC) - timedelta(seconds=_max_session_seconds())
    keep = []
    for stmt in statements:
        issued_before = stmt.get("Condition", {}).get("DateLessThan", {}).get("aws:TokenIssueTime")
        revoked_at = (
            datetime.strptime(issued_before, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) if issued_before else None
        )
        if revoked_at is None or revoked_at > horizon:
            keep.append(stmt)
    if len(keep) != len(statements):
        _save_revocations(iam, role, keep)
    return len(statements) - len(keep)
