"""Access recertification campaigns: certify, revoke, and fail closed at the deadline."""

from datetime import timedelta

from conftest import ALICE, BOB, FRANK, GRACE, MAYA

from app import certification
from app.database import SessionLocal, utcnow
from app.models import CertificationCampaign


def _grant(client, headers, text="read prod-db for 8 hours to debug"):
    body = client.post("/request-access", json={"request_text": text}, headers=headers).json()
    assert body["status"] == "ACTIVE", body
    return body["request_id"]


def _start(client, auth, **extra):
    resp = client.post("/certifications", json={"name": "Q3 recertification", **extra}, headers=auth(GRACE))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _status(client, auth, request_id):
    return client.get(f"/requests/{request_id}", headers=auth(GRACE)).json()


def test_campaign_snapshots_active_grants(client, auth):
    grant = _grant(client, auth(ALICE))
    campaign = _start(client, auth)
    assert campaign["status"] == "OPEN" and campaign["counts"]["total"] == 1
    assert campaign["items"][0]["request"]["id"] == grant
    listed = client.get("/certifications", headers=auth(GRACE)).json()
    assert listed[0]["counts"]["pending"] == 1
    assert (
        client.get(f"/certifications/{campaign['id']}", headers=auth(GRACE)).json()["items"][0]["decision"] == "PENDING"
    )
    assert client.get("/certifications/999", headers=auth(GRACE)).status_code == 404
    logs = client.get("/audit-logs", params={"event": "CERTIFICATION_STARTED"}, headers=auth(GRACE)).json()
    assert "1 grants to review" in logs[0]["detail"]


def test_only_oversight_starts_campaigns(client, auth):
    assert client.post("/certifications", json={"name": "mine"}, headers=auth(ALICE)).status_code == 403
    assert client.get("/certifications", headers=auth(MAYA)).status_code == 403


def test_reviewer_certifies_and_grant_stays(client, auth):
    grant = _grant(client, auth(ALICE))
    _start(client, auth)
    tasks = [t for t in client.get("/approvals", headers=auth(MAYA)).json() if t["kind"] == "certification"]
    assert len(tasks) == 1 and tasks[0]["request"]["id"] == grant
    item = tasks[0]["certification"]["item_id"]

    # Separation of duties: not the grantee, not someone unrelated.
    for who in (ALICE, FRANK):
        assert (
            client.post(
                f"/certifications/items/{item}/certify", json={"comment": "fine"}, headers=auth(who)
            ).status_code
            == 403
        )
    resp = client.post(f"/certifications/items/{item}/certify", json={"comment": "Still debugging"}, headers=auth(MAYA))
    assert resp.status_code == 200 and resp.json()["decision"] == "CERTIFIED"
    assert _status(client, auth, grant)["status"] == "ACTIVE"
    again = client.post(f"/certifications/items/{item}/revoke", json={"comment": "changed mind"}, headers=auth(MAYA))
    assert again.status_code == 409
    assert not [t for t in client.get("/approvals", headers=auth(MAYA)).json() if t["kind"] == "certification"]


def test_reviewer_revokes(client, auth):
    grant = _grant(client, auth(ALICE))
    item = _start(client, auth)["items"][0]["id"]
    resp = client.post(f"/certifications/items/{item}/revoke", json={"comment": "No longer needed"}, headers=auth(MAYA))
    assert resp.json()["decision"] == "REVOKED"
    detail = _status(client, auth, grant)
    assert detail["status"] == "REVOKED" and detail["revoke_reason"].startswith("Recertification")


def test_deadline_revokes_whatever_was_not_certified(client, auth):
    kept = _grant(client, auth(ALICE))
    dropped = _grant(client, auth(BOB), "read ci-pipeline for 24 hours to fix the build")
    campaign = _start(client, auth, due_in_hours=1)
    items = {i["request"]["id"]: i["id"] for i in campaign["items"]}
    client.post(f"/certifications/items/{items[kept]}/certify", json={"comment": "Still needed"}, headers=auth(MAYA))

    assert certification.close_overdue() == 0  # not due yet
    with SessionLocal() as db:
        db.get(CertificationCampaign, campaign["id"]).due_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert certification.close_overdue() == 1
    assert _status(client, auth, kept)["status"] == "ACTIVE"
    assert _status(client, auth, dropped)["status"] == "REVOKED"
    closed = client.get(f"/certifications/{campaign['id']}", headers=auth(GRACE)).json()
    assert closed["status"] == "CLOSED" and closed["counts"] == {
        "pending": 0,
        "certified": 1,
        "revoked": 1,
        "ended": 0,
        "total": 2,
    }
    assert client.get("/audit-logs/verify", headers=auth(GRACE)).json()["valid"] is True


def test_grants_that_end_first_are_marked_ended(client, auth):
    alice = auth(ALICE)
    grant = _grant(client, alice)
    item = _start(client, auth)["items"][0]["id"]
    client.post(f"/grants/{grant}/revoke", json={"reason": "done early"}, headers=alice)
    resp = client.post(f"/certifications/items/{item}/certify", json={"comment": "fine"}, headers=auth(MAYA))
    assert resp.status_code == 409
    items = client.get("/certifications", headers=auth(GRACE)).json()[0]["counts"]
    assert items["ended"] == 1
