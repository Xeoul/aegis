"""MFA step-up: TOTP (RFC 6238), the RFC 9470 challenge, replay and brute-force protection."""

import base64
import dataclasses
from datetime import UTC, datetime, timedelta

import jwt
from conftest import ALICE, BOB, GRACE, IRIS, MAYA

from app import mfa
from app.auth import create_dev_token
from app.config import settings
from app.database import SessionLocal, utcnow
from app.models import User

RESTRICTED = {"request_text": "Need admin on prod-k8s-cluster for 2 hours to roll back a bad deploy"}


def _enroll(client, headers):
    resp = client.post("/auth/mfa/enroll", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _step_up(client, headers, code):
    return client.post("/auth/step-up", json={"code": code}, headers=headers)


def _bearer(resp):
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def test_totp_matches_rfc_6238_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.totp(secret, datetime.fromtimestamp(59, UTC)) == "287082"
    assert mfa.totp(secret, datetime.fromtimestamp(1111111109, UTC)) == "081804"
    assert mfa.totp(secret, datetime.fromtimestamp(2000000000, UTC)) == "279037"


def test_verify_allows_drift_but_not_replay_or_garbage():
    secret, now = mfa.new_secret(), utcnow()
    previous = mfa.totp(secret, now - timedelta(seconds=30))
    step = mfa.verify(secret, previous, now, None)
    assert step == mfa.step_at(now) - 1
    assert mfa.verify(secret, previous, now, step) is None  # already used
    assert mfa.verify(secret, mfa.totp(secret, now - timedelta(minutes=5)), now, None) is None
    assert mfa.verify(secret, "12a456", now, None) is None
    assert mfa.otpauth_uri(secret, ALICE).startswith("otpauth://totp/Aegis-JIT%3Aalice.chen")


def test_enroll_then_step_up_issues_an_mfa_token(client, auth):
    plain = auth(ALICE, mfa=False)
    assert client.get("/me", headers=plain).json()["mfa_enrolled"] is False
    secret = _enroll(client, plain)["secret"]
    resp = _step_up(client, plain, mfa.totp(secret, utcnow()))
    assert resp.status_code == 200, resp.text
    claims = jwt.decode(resp.json()["access_token"], options={"verify_signature": False})
    assert {"otp", "mfa"} <= set(claims["amr"]) and claims["acr"] == mfa.ACR_MFA
    assert abs(claims["auth_time"] - utcnow().replace(tzinfo=UTC).timestamp()) < 5
    assert client.get("/me", headers=plain).json()["mfa_enrolled"] is True
    events = [e["event"] for e in client.get("/audit-logs", headers=auth(GRACE)).json()]
    assert "MFA_ENROLLED" in events


def test_restricted_request_gets_rfc_9470_challenge_then_succeeds(client, auth):
    plain = auth(BOB, mfa=False)
    resp = client.post("/request-access", json=RESTRICTED, headers=plain)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "insufficient_user_authentication"
    challenge = resp.headers["www-authenticate"]
    assert 'error="insufficient_user_authentication"' in challenge and "max_age=900" in challenge
    assert client.get("/requests", headers=plain).json() == []  # nothing recorded
    logs = client.get("/audit-logs", params={"event": "STEP_UP_REQUIRED"}, headers=auth(GRACE)).json()
    assert logs and logs[0]["resource"] == "prod-k8s-cluster"

    secret = _enroll(client, plain)["secret"]
    stepped = _bearer(_step_up(client, plain, mfa.totp(secret, utcnow())))
    pending = client.post("/request-access", json=RESTRICTED, headers=stepped).json()
    assert pending["status"] == "PENDING_APPROVAL"


def test_lower_risk_requests_need_no_step_up(client, auth):
    resp = client.post(
        "/request-access", json={"request_text": "read prod-db for 2 hours to debug"}, headers=auth(ALICE, mfa=False)
    )
    assert resp.status_code == 200 and resp.json()["status"] == "ACTIVE"


def test_break_glass_needs_step_up(client, auth):
    body = {"request_text": "Admin on prod-k8s-cluster now to stop a live outage", "break_glass": True}
    assert client.post("/request-access", json=body, headers=auth(BOB, mfa=False)).status_code == 401
    assert client.post("/request-access", json=body, headers=auth(BOB)).json()["status"] == "ACTIVE"


def test_denied_requests_are_denied_not_challenged(client, auth):
    resp = client.post("/request-access", json=RESTRICTED, headers=auth(ALICE, mfa=False))
    assert resp.status_code == 200 and resp.json()["decision"] == "DENY"
    assert not any("mfa-required" in r for r in resp.json()["reasons"])


def test_approver_must_step_up(client, auth):
    pending = client.post("/request-access", json=RESTRICTED, headers=auth(BOB)).json()
    url = f"/requests/{pending['request_id']}/approve"
    resp = client.post(url, json={"comment": "ok for rollback"}, headers=auth(MAYA, mfa=False))
    assert resp.status_code == 401 and "max_age" in resp.headers["www-authenticate"]
    resp = client.post(url, json={"comment": "ok for rollback"}, headers=auth(MAYA))
    assert resp.status_code == 200 and resp.json()["status"] == "ACTIVE"


def test_mfa_goes_stale(client, auth):
    with SessionLocal() as db:
        bob = db.query(User).filter(User.email == BOB).one()
        token, _ = create_dev_token(bob, mfa_at=utcnow() - timedelta(minutes=settings.mfa_max_age_minutes + 1))
    resp = client.post("/request-access", json=RESTRICTED, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_codes_cannot_be_replayed(client, auth):
    plain = auth(ALICE, mfa=False)
    secret = _enroll(client, plain)["secret"]
    code = mfa.totp(secret, utcnow())
    assert _step_up(client, plain, code).status_code == 200
    assert _step_up(client, plain, code).status_code == 401


def test_step_up_needs_enrollment(client, auth):
    resp = _step_up(client, auth(ALICE, mfa=False), "123456")
    assert resp.status_code == 409


def test_replacing_an_authenticator_needs_the_current_one(client, auth):
    plain = auth(ALICE, mfa=False)
    secret = _enroll(client, plain)["secret"]
    stepped = _bearer(_step_up(client, plain, mfa.totp(secret, utcnow())))
    assert client.post("/auth/mfa/enroll", headers=plain).status_code == 401  # a stolen plain token isn't enough
    assert client.post("/auth/mfa/enroll", headers=stepped).status_code == 200


def test_brute_force_locks_and_alerts_then_admin_resets(client, auth):
    plain = auth(ALICE, mfa=False)
    secret = _enroll(client, plain)["secret"]
    wrong = str((int(mfa.totp(secret, utcnow())) + 1) % 1_000_000).zfill(6)
    for _ in range(mfa.MAX_FAILURES):
        assert _step_up(client, plain, wrong).status_code == 401
    assert _step_up(client, plain, mfa.totp(secret, utcnow())).status_code == 423
    alerts = client.get("/alerts", headers=auth(GRACE)).json()
    assert any(a["rule"] == "mfa-brute-force" and a["severity"] == "high" for a in alerts)

    with SessionLocal() as db:
        alice_id = db.query(User).filter(User.email == ALICE).one().id
        iris_id = db.query(User).filter(User.email == IRIS).one().id
    assert client.post(f"/users/{alice_id}/mfa/reset", headers=auth(ALICE)).status_code == 403
    assert client.post(f"/users/{iris_id}/mfa/reset", headers=auth(IRIS)).status_code == 403
    assert client.post(f"/users/{alice_id}/mfa/reset", headers=auth(IRIS)).json()["mfa_enrolled"] is False
    secret = _enroll(client, plain)["secret"]
    assert _step_up(client, plain, mfa.totp(secret, utcnow())).status_code == 200
    assert client.get("/audit-logs/verify", headers=auth(GRACE)).json()["valid"] is True


def test_oidc_claims_count_as_mfa(monkeypatch):
    oidc = dataclasses.replace(
        settings, auth_mode="oidc", oidc_issuer="https://idp", oidc_jwks_url="https://idp/jwks", oidc_mfa_acr=("gold",)
    )
    monkeypatch.setattr(mfa, "settings", oidc)
    now = utcnow()
    recent = int(now.replace(tzinfo=UTC).timestamp()) - 60
    assert mfa.is_fresh({"amr": ["pwd", "hwk"], "auth_time": recent}, now)
    assert mfa.is_fresh({"acr": "gold", "auth_time": recent}, now)
    assert not mfa.is_fresh({"acr": mfa.ACR_MFA, "auth_time": recent}, now)  # dev issuer's acr isn't trusted
    assert not mfa.is_fresh({"amr": ["pwd"], "auth_time": recent}, now)
    assert not mfa.is_fresh({"amr": ["otp"], "auth_time": recent - 3600}, now)


def test_mfa_endpoints_disabled_in_oidc_mode(client, auth, monkeypatch):
    headers = auth(ALICE, mfa=False)
    monkeypatch.setattr("app.config.settings", type("S", (), {"auth_mode": "oidc"})())
    assert client.post("/auth/step-up", json={"code": "123456"}, headers=headers).status_code == 404
