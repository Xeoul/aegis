from conftest import ALICE, GRACE, IRIS
from sqlalchemy import text

from app.database import SessionLocal


def _populate(client, auth):
    alice = auth(ALICE)
    for text_ in ["read prod-db for 2 hours to debug", "delete kms-master-keys now", "read company-wiki"]:
        client.post("/request-access", json={"request_text": text_}, headers=alice)


def _verify(client, auth):
    return client.get("/audit-logs/verify", headers=auth(GRACE)).json()


def test_chain_is_valid_and_linked(client, auth):
    _populate(client, auth)
    result = _verify(client, auth)
    assert result["valid"] is True and result["entries_checked"] == 6
    logs = client.get("/audit-logs", headers=auth(GRACE)).json()[::-1]
    assert logs[0]["prev_hash"] == "0" * 64
    assert all(b["prev_hash"] == a["hash"] for a, b in zip(logs, logs[1:], strict=False))


def test_detects_edited_entry(client, auth):
    _populate(client, auth)
    with SessionLocal() as db:
        db.execute(text("UPDATE audit_logs SET detail = 'nothing to see here' WHERE id = 3"))
        db.commit()
    result = _verify(client, auth)
    assert result["valid"] is False
    assert result["first_invalid_id"] == 3
    assert "hash" in result["reason"]


def test_detects_deleted_entry(client, auth):
    _populate(client, auth)
    with SessionLocal() as db:
        db.execute(text("DELETE FROM audit_logs WHERE id = 2"))
        db.commit()
    result = _verify(client, auth)
    assert result["valid"] is False and result["first_invalid_id"] == 3


def test_admin_actions_are_audited(client, auth):
    body = {"name": "Zed", "email": "zed@aegis.example", "department": "Legal", "role": "analyst"}
    client.post("/users", json=body, headers=auth(IRIS))
    logs = client.get("/audit-logs", params={"event": "USER_CREATED"}, headers=auth(GRACE)).json()
    assert len(logs) == 1 and logs[0]["actor_id"] == 9
    assert _verify(client, auth)["valid"] is True
