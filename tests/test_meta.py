from app import scheduler


def test_meta_is_public_and_has_no_secrets(client):
    body = client.get("/meta").json()
    assert body["demo_mode"] is False and body["parser"] == "heuristic" and body["credential_broker"] == "none"
    assert not any("secret" in k or "key" in k for k in body)


def test_demo_mode_reports_next_reset(client, monkeypatch):
    from datetime import UTC, datetime

    monkeypatch.setattr(
        "app.main.settings", type("S", (), {"demo_mode": True, "auth_mode": "dev", "demo_reset_minutes": 180})()
    )
    monkeypatch.setattr(scheduler, "last_demo_reset", datetime(2026, 1, 1, tzinfo=UTC))
    body = client.get("/meta").json()
    assert body["demo_mode"] is True and body["next_reset_at"].startswith("2026-01-01T03:00")


def test_demo_reset_wipes_activity(client, auth):
    from conftest import ALICE, GRACE

    client.post("/request-access", json={"request_text": "read prod-db for 2 hours to debug"}, headers=auth(ALICE))
    scheduler.reset_demo_data()
    assert client.get("/audit-logs", headers=auth(GRACE)).json() == []
    assert len(client.get("/users", headers=auth(GRACE)).json()) == 10
