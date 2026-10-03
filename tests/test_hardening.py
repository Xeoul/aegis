"""Rate limiting and signed audit checkpoints (truncation detection)."""

import base64
import dataclasses
import json

from conftest import ALICE, GRACE
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import delete, func, select

from app import audit, checkpoints, ratelimit
from app.config import settings
from app.database import SessionLocal
from app.models import AuditLog

# --- Rate limiting ----------------------------------------------------------------


def test_token_bucket_refills_and_reports_first_refusal():
    bucket = ratelimit.TokenBucket(2, 60)
    assert bucket.take("k", now=0)[0] and bucket.take("k", now=0)[0]
    allowed, wait, first = bucket.take("k", now=0)
    assert not allowed and round(wait) == 30 and first
    assert (
        bucket.take("k", now=1) == (False, bucket.take("other", now=1)[1] or 29.0, False)
        or not bucket.take("k", now=1)[0]
    )
    assert bucket.take("k", now=31)[0]  # a token came back


def test_bucket_memory_is_bounded(monkeypatch):
    monkeypatch.setattr(ratelimit, "MAX_KEYS", 3)
    bucket = ratelimit.TokenBucket(1, 60)
    for key in "abcde":
        bucket.take(key, now=0)
    assert list(bucket._buckets) == ["c", "d", "e"]


def test_sign_in_is_rate_limited_and_audited_once(client, auth):
    codes = [client.post("/auth/dev-token", json={"email": ALICE}).status_code for _ in range(32)]
    assert codes[:30] == [200] * 30 and codes[30:] == [429, 429]
    resp = client.post("/auth/dev-token", json={"email": ALICE})
    assert int(resp.headers["retry-after"]) >= 1
    logs = client.get("/audit-logs", params={"event": "RATE_LIMITED"}, headers=auth(GRACE)).json()
    assert len(logs) == 1 and logs[0]["detail"].startswith("sign-in")


def test_rate_limits_can_be_turned_off(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "settings", dataclasses.replace(settings, rate_limits=False))
    assert all(client.post("/auth/dev-token", json={"email": ALICE}).status_code == 200 for _ in range(35))


# --- Signed checkpoints -------------------------------------------------------------


def _activity(client, auth):
    client.post("/request-access", json={"request_text": "read prod-db for 2 hours to debug"}, headers=auth(ALICE))


def _verify(client, auth):
    return client.get("/audit-logs/verify", headers=auth(GRACE)).json()


def _checkpoint(client, auth):
    return client.post("/audit-logs/checkpoints", headers=auth(GRACE)).json()


def test_no_checkpoint_for_an_empty_log(client):
    with SessionLocal() as db:
        assert checkpoints.create(db) is None


def test_checkpoints_are_signed_with_the_published_key(client, auth):
    _activity(client, auth)
    first = _checkpoint(client, auth)
    assert first["seq"] == 1 and first["prev"] == checkpoints.GENESIS
    assert _checkpoint(client, auth)["seq"] == 1  # nothing new to vouch for
    _activity(client, auth)
    assert _checkpoint(client, auth)["seq"] == 2

    listing = client.get("/audit-logs/checkpoints", headers=auth(GRACE)).json()
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(listing["public_key"]))
    for cp in listing["checkpoints"]:
        fields = {k: v for k, v in cp.items() if k != "signature"}
        key.verify(
            base64.b64decode(cp["signature"]), json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        )
    assert listing["algorithm"] == "Ed25519" and listing["key_id"] == cp["key_id"]
    result = _verify(client, auth)
    assert result["valid"] and result["checkpoints_checked"] == 2
    assert client.get("/audit-logs/checkpoints", headers=auth(ALICE)).status_code == 403


def test_truncating_the_log_is_caught(client, auth):
    _activity(client, auth)
    cp = _checkpoint(client, auth)
    with SessionLocal() as db:
        # Someone with database access deletes the newest entries. The HMAC chain that's left
        # is still valid, so only the checkpoint can tell.
        db.execute(delete(AuditLog).where(AuditLog.id > cp["head_id"] - 2))
        db.commit()
        assert db.scalar(select(func.count()).select_from(AuditLog)) == cp["entries"] - 2
    result = _verify(client, auth)
    assert not result["valid"] and result["first_invalid_id"] == cp["head_id"]
    assert "deleted" in result["reason"]


def test_entries_after_the_last_checkpoint_are_the_exposure_window(client, auth):
    _activity(client, auth)
    cp = _checkpoint(client, auth)
    _activity(client, auth)
    with SessionLocal() as db:
        db.execute(delete(AuditLog).where(AuditLog.id > cp["head_id"]))
        db.commit()
    assert _verify(client, auth)["valid"]  # documented limitation: checkpoint often


def test_editing_or_removing_checkpoints_is_caught(client, auth):
    for _ in range(3):
        _activity(client, auth)
        _checkpoint(client, auth)
    path = checkpoints._path()
    lines = path.read_text().splitlines()

    forged = json.loads(lines[0])
    forged["entries"] += 5
    path.write_text("\n".join([json.dumps(forged), *lines[1:]]) + "\n")
    assert "invalid signature" in _verify(client, auth)["reason"]

    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert "removed or reordered" in _verify(client, auth)["reason"]


def test_rewriting_an_entry_with_the_hmac_key_is_caught(client, auth):
    _activity(client, auth)
    cp = _checkpoint(client, auth)
    with SessionLocal() as db:
        # An insider with the HMAC key edits the newest entry and recomputes its hash, so the
        # chain verifies. The checkpoint was signed with a different key.
        head = db.get(AuditLog, cp["head_id"])
        head.detail = "nothing to see here"
        head.hash = audit.compute_hash(head.prev_hash, head)
        db.commit()
    result = _verify(client, auth)
    assert not result["valid"] and "rewritten" in result["reason"]


def test_scheduler_job_and_reset(client, auth):
    _activity(client, auth)
    checkpoints.create_now()
    assert len(checkpoints.read_all()) == 1
    client.post("/auth/dev-token", json={"email": ALICE})
    from seed_data import seed

    seed(reset=True)
    assert checkpoints.read_all() == []
