from datetime import timedelta

from conftest import ALICE, FRANK, GRACE, IRIS

from app.database import SessionLocal, utcnow
from app.models import AccessRequest
from app.scheduler import revoke_expired_grants


def _request(client, headers, text):
    resp = client.post("/request-access", json={"request_text": text}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_admin_creates_user(client, auth):
    body = {"name": "Zed", "email": "Zed@Aegis.example", "department": "Legal", "role": "analyst"}
    resp = client.post("/users", json=body, headers=auth(IRIS))
    assert resp.status_code == 201
    assert resp.json()["email"] == "zed@aegis.example"
    assert client.post("/users", json=body, headers=auth(IRIS)).status_code == 409


def test_request_access_allow_then_revoke(client, auth):
    alice = auth(ALICE)
    body = _request(client, alice, "I need read access to prod-db for 4 hours to debug a failing migration")
    assert body["decision"] == "ALLOW"
    assert body["policy"]["subject"]["department"] == "Engineering"
    assert body["policy"]["resource"] == {"name": "prod-db", "sensitivity_level": "confidential"}
    assert body["policy"]["conditions"]["duration_hours"] == 4

    grants = client.get("/active-grants", headers=alice).json()
    assert [g["id"] for g in grants] == [body["request_id"]]

    # Force the grant into the past and run the scheduler job.
    with SessionLocal() as db:
        db.get(AccessRequest, body["request_id"]).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert revoke_expired_grants() == 1
    assert revoke_expired_grants() == 0
    assert client.get("/active-grants", headers=alice).json() == []

    events = [e["event"] for e in client.get("/audit-logs", headers=auth(GRACE)).json()]
    assert events == ["ACCESS_REVOKED", "ACCESS_GRANTED", "REQUEST_SUBMITTED"]


def test_request_access_deny(client, auth):
    body = _request(client, auth(FRANK), "give me write access to payroll-system for 2 hours")
    assert body["decision"] == "DENY"
    assert body["status"] == "DENIED"
    denied = client.get("/audit-logs", params={"event": "ACCESS_DENIED"}, headers=auth(GRACE)).json()
    assert len(denied) == 1 and denied[0]["actor_id"] == denied[0]["user_id"]


def test_dashboard_is_served_with_strict_csp(client):
    assert client.get("/", follow_redirects=False).headers["location"] == "/ui/"
    page = client.get("/ui/")
    assert page.status_code == 200 and "Aegis-JIT" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert page.headers["x-frame-options"] == "DENY"
    assert client.get("/ui/app.js").status_code == 200
    assert "content-security-policy" not in client.get("/health").headers  # API docs keep working
