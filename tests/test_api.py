from datetime import timedelta

from app.database import SessionLocal, utcnow
from app.models import AccessRequest
from app.scheduler import revoke_expired_grants


def test_create_user(client):
    resp = client.post("/users", json={"name": "Zed", "department": "Legal", "role": "analyst"})
    assert resp.status_code == 201
    assert resp.json()["id"] > 0


def test_request_access_allow_then_revoke(client):
    resp = client.post(
        "/request-access",
        json={"user_id": 1, "request_text": "I need read access to prod-db for 4 hours to debug a failing migration"},
    )
    body = resp.json()
    assert resp.status_code == 200, body
    assert body["decision"] == "ALLOW"
    assert body["policy"]["resource"] == {"name": "prod-db", "sensitivity_level": "confidential"}
    assert body["policy"]["conditions"]["duration_hours"] == 4

    grants = client.get("/active-grants").json()
    assert [g["id"] for g in grants] == [body["request_id"]]

    # Force the grant into the past and run the scheduler job.
    with SessionLocal() as db:
        db.get(AccessRequest, body["request_id"]).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert revoke_expired_grants() == 1
    assert revoke_expired_grants() == 0
    assert client.get("/active-grants").json() == []

    events = [e["event"] for e in client.get("/audit-logs").json()]
    assert events == ["ACCESS_REVOKED", "ACCESS_GRANTED", "REQUEST_SUBMITTED"]


def test_request_access_deny(client):
    resp = client.post(
        "/request-access",
        json={"user_id": 6, "request_text": "give me write access to payroll-system for 2 hours"},
    )
    body = resp.json()
    assert body["decision"] == "DENY"
    assert body["status"] == "DENIED"
    assert client.get("/active-grants").json() == []
    denied = client.get("/audit-logs", params={"event": "ACCESS_DENIED"}).json()
    assert len(denied) == 1 and denied[0]["user_id"] == 6


def test_request_access_unknown_user(client):
    resp = client.post("/request-access", json={"user_id": 999, "request_text": "read prod-db please"})
    assert resp.status_code == 404
