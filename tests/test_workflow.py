from datetime import timedelta

import pytest
from conftest import ALICE, BOB, DAN, EVE, FRANK, GRACE, HANK, IRIS, MAYA

from app.database import SessionLocal, utcnow
from app.models import AccessRequest
from app.scheduler import expire_stale_requests

K8S_ADMIN = "Need admin on prod-k8s-cluster for 6 hours to roll back a bad deploy"


def _submit(client, headers, text, **extra):
    resp = client.post("/request-access", json={"request_text": text, **extra}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _events(client, auth, request_id):
    logs = client.get("/audit-logs", headers=auth(GRACE)).json()
    return [e["event"] for e in reversed(logs) if e["request_id"] == request_id]


def test_high_risk_request_waits_for_approval(client, auth):
    bob = auth(BOB)
    body = _submit(client, bob, K8S_ADMIN)
    assert body["decision"] == "ALLOW"
    assert body["status"] == "PENDING_APPROVAL" and body["requires_approval"] is True
    assert body["approval_deadline"] is not None
    assert client.get("/active-grants", headers=bob).json() == []

    tasks = client.get("/approvals", headers=auth(MAYA)).json()
    assert [(t["kind"], t["request"]["id"]) for t in tasks] == [("approval", body["request_id"])]

    resp = client.post(f"/requests/{body['request_id']}/approve", json={"comment": "Incident INC-7"}, headers=auth(MAYA))
    assert resp.status_code == 200, resp.text
    grant = resp.json()
    assert grant["status"] == "ACTIVE" and grant["decided_by_id"] == 10 and grant["duration_hours"] == 2
    assert [g["id"] for g in client.get("/active-grants", headers=bob).json()] == [body["request_id"]]
    assert _events(client, auth, body["request_id"]) == [
        "REQUEST_SUBMITTED",
        "APPROVAL_REQUIRED",
        "REQUEST_APPROVED",
        "ACCESS_GRANTED",
    ]


def test_low_risk_request_is_granted_immediately(client, auth):
    body = _submit(client, auth(ALICE), "read prod-db for 2 hours to debug a report")
    assert body["status"] == "ACTIVE" and body["requires_approval"] is False


@pytest.mark.parametrize(
    "approver, expected",
    [
        (BOB, 403),  # the requester: separation of duties
        (ALICE, 403),  # peer, not a manager
        (DAN, 403),  # manager, but of a different department
        (IRIS, 403),  # identity admin: not an approver
        (GRACE, 403),  # auditor: oversight, not approval
        (EVE, 200),  # security engineer
        (MAYA, 200),  # requester's manager
    ],
)
def test_approver_eligibility(client, auth, approver, expected):
    body = _submit(client, auth(BOB), K8S_ADMIN)
    resp = client.post(f"/requests/{body['request_id']}/approve", json={"comment": "ok by me"}, headers=auth(approver))
    assert resp.status_code == expected, resp.text


def test_self_approval_blocked_even_for_approver_roles(client, auth):
    eve = auth(EVE)
    body = _submit(client, eve, "admin on kms-master-keys for 1 hour because of quarterly key rotation")
    assert body["status"] == "PENDING_APPROVAL"
    resp = client.post(f"/requests/{body['request_id']}/approve", json={"comment": "self"}, headers=eve)
    assert resp.status_code == 403 and "Separation of duties" in resp.json()["detail"]
    assert client.get("/approvals", headers=eve).json() == []


def test_reject(client, auth):
    body = _submit(client, auth(BOB), K8S_ADMIN)
    resp = client.post(f"/requests/{body['request_id']}/reject", json={"comment": "use the runbook"}, headers=auth(MAYA))
    assert resp.json()["status"] == "REJECTED"
    again = client.post(f"/requests/{body['request_id']}/approve", json={"comment": "oops"}, headers=auth(MAYA))
    assert again.status_code == 409


def test_policy_is_rechecked_at_approval_time(client, auth):
    body = _submit(client, auth(BOB), K8S_ADMIN)
    with SessionLocal() as db:  # Bob's role changes out-of-band before approval
        db.get(AccessRequest, body["request_id"]).user.role = "engineer"
        db.commit()
    resp = client.post(f"/requests/{body['request_id']}/approve", json={"comment": "approved"}, headers=auth(MAYA))
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "DENIED"
    assert "cleared up to confidential" in resp.json()["decision_reason"]


def test_pending_requests_expire(client, auth):
    body = _submit(client, auth(BOB), K8S_ADMIN)
    with SessionLocal() as db:
        db.get(AccessRequest, body["request_id"]).approval_deadline = utcnow() - timedelta(seconds=1)
        db.commit()
    resp = client.post(f"/requests/{body['request_id']}/approve", json={"comment": "late"}, headers=auth(MAYA))
    assert resp.status_code == 409
    assert expire_stale_requests() == 1
    assert client.get(f"/requests/{body['request_id']}", headers=auth(BOB)).json()["status"] == "EXPIRED"


def test_break_glass_grants_immediately_and_requires_review(client, auth):
    bob = auth(BOB)
    body = _submit(client, bob, K8S_ADMIN + " because prod is down", break_glass=True)
    assert body["status"] == "ACTIVE" and body["break_glass"] is True
    assert body["policy"]["conditions"]["duration_hours"] == 1

    tasks = client.get("/approvals", headers=auth(EVE)).json()
    assert [t["kind"] for t in tasks] == ["break_glass_review"]
    assert client.post(f"/requests/{body['request_id']}/review", json={"comment": "self"}, headers=bob).status_code == 403
    resp = client.post(f"/requests/{body['request_id']}/review", json={"comment": "Justified, INC-9"}, headers=auth(EVE))
    assert resp.json()["reviewed_by_id"] == 5
    assert client.get("/approvals", headers=auth(EVE)).json() == []
    assert "BREAK_GLASS_REVIEWED" in _events(client, auth, body["request_id"])


def test_break_glass_does_not_bypass_policy(client, auth):
    body = _submit(client, auth(HANK), K8S_ADMIN + " because prod is down", break_glass=True)
    assert body["decision"] == "DENY" and body["status"] == "DENIED"


def test_manual_revoke(client, auth):
    alice = auth(ALICE)
    body = _submit(client, alice, "read prod-db for 4 hours to debug")
    assert client.post(f"/grants/{body['request_id']}/revoke", json={"reason": "nope"}, headers=auth(FRANK)).status_code == 403
    resp = client.post(f"/grants/{body['request_id']}/revoke", json={"reason": "done early"}, headers=alice)
    assert resp.json()["status"] == "REVOKED" and resp.json()["revoked_by_id"] == 1
    assert client.get("/active-grants", headers=alice).json() == []
    assert client.post(f"/grants/{body['request_id']}/revoke", json={"reason": "again"}, headers=alice).status_code == 409


def test_leaver_loses_all_access(client, auth):
    alice = auth(ALICE)
    grant = _submit(client, alice, "read prod-db for 4 hours to debug")
    resp = client.patch("/users/1", json={"is_active": False}, headers=auth(IRIS))
    assert resp.status_code == 200 and resp.json()["is_active"] is False
    assert client.get("/me", headers=alice).status_code == 403
    grants = client.get("/active-grants", params={"user_id": 1}, headers=auth(GRACE)).json()
    assert grants == []
    assert _events(client, auth, grant["request_id"])[-1] == "ACCESS_REVOKED"


def test_mover_access_is_revoked_and_admin_cannot_self_modify(client, auth):
    grant = _submit(client, auth(ALICE), "read prod-db for 4 hours to debug")
    assert client.patch("/users/1", json={"department": "Finance"}, headers=auth(IRIS)).status_code == 200
    detail = client.get(f"/requests/{grant['request_id']}", headers=auth(GRACE)).json()
    assert detail["status"] == "REVOKED" and detail["revoke_reason"].startswith("Mover")
    assert client.patch("/users/9", json={"role": "sre"}, headers=auth(IRIS)).status_code == 403
    assert client.patch("/users/2", json={"role": "admin"}, headers=auth(ALICE)).status_code == 403


def test_request_visibility(client, auth):
    body = _submit(client, auth(BOB), K8S_ADMIN)
    rid = body["request_id"]
    assert client.get(f"/requests/{rid}", headers=auth(BOB)).status_code == 200
    assert client.get(f"/requests/{rid}", headers=auth(MAYA)).status_code == 200  # approver
    assert client.get(f"/requests/{rid}", headers=auth(ALICE)).status_code == 404
    assert [r["id"] for r in client.get("/requests", headers=auth(BOB)).json()] == [rid]
