from datetime import timedelta

import jwt
import pytest
from conftest import ALICE, FRANK, GRACE, IRIS

from app.auth import DEV_AUDIENCE, DEV_ISSUER
from app.config import settings
from app.database import SessionLocal, utcnow
from app.models import User


def _token(email, *, secret=None, **overrides):
    now = utcnow()
    claims = {
        "iss": DEV_ISSUER,
        "aud": DEV_AUDIENCE,
        "sub": "1",
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    token = jwt.encode(claims, secret or settings.jwt_secret, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", ["/me", "/users", "/resources", "/active-grants", "/audit-logs"])
def test_endpoints_require_a_token(client, path):
    assert client.get(path).status_code == 401


def test_request_access_requires_a_token(client):
    assert client.post("/request-access", json={"request_text": "read prod-db please"}).status_code == 401


def test_identity_comes_from_token_not_body(client, auth):
    # The old API accepted user_id in the body; it must be ignored now.
    resp = client.post(
        "/request-access", json={"user_id": 2, "request_text": "read access to prod-db for 1 hour"}, headers=auth(FRANK)
    )
    assert resp.json()["policy"]["subject"]["role"] == "intern"


@pytest.mark.parametrize(
    "headers",
    [
        _token(ALICE, secret="an-attacker-controlled-secret-of-32-bytes"),
        _token(ALICE, exp=utcnow() - timedelta(minutes=1)),
        _token(ALICE, aud="someone-else"),
        _token(ALICE, iss="https://evil.example"),
        {"Authorization": "Bearer not-a-jwt"},
    ],
    ids=["bad-signature", "expired", "wrong-audience", "wrong-issuer", "garbage"],
)
def test_rejects_invalid_tokens(client, headers):
    assert client.get("/me", headers=headers).status_code == 401


def test_rejects_alg_none(client):
    now = utcnow()
    claims = {"iss": DEV_ISSUER, "aud": DEV_AUDIENCE, "email": ALICE, "iat": now, "exp": now + timedelta(minutes=5)}
    token = jwt.encode(claims, key=None, algorithm="none")
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_unprovisioned_and_deactivated_users_are_forbidden(client, auth):
    assert client.get("/me", headers=_token("stranger@aegis.example")).status_code == 403
    headers = auth(ALICE)
    with SessionLocal() as db:
        db.query(User).filter(User.email == ALICE).update({"is_active": False})
        db.commit()
    assert client.get("/me", headers=headers).status_code == 403
    assert client.post("/auth/dev-token", json={"email": ALICE}).status_code == 401


def test_only_admins_create_users(client, auth):
    body = {"name": "Mallory", "email": "mallory@aegis.example", "department": "IT", "role": "admin", "is_admin": True}
    assert client.post("/users", json=body, headers=auth(ALICE)).status_code == 403
    assert client.post("/users", json=body, headers=auth(IRIS)).status_code == 201


def test_audit_logs_limited_to_oversight_roles(client, auth):
    assert client.get("/audit-logs", headers=auth(ALICE)).status_code == 403
    assert client.get("/audit-logs", headers=auth(GRACE)).status_code == 200
    assert client.get("/audit-logs/verify", headers=auth(ALICE)).status_code == 403


def test_users_only_see_their_own_grants(client, auth):
    alice = auth(ALICE)
    client.post("/request-access", json={"request_text": "read company-wiki for 1 hour"}, headers=auth(FRANK))
    assert client.get("/active-grants", headers=alice).json() == []
    assert client.get("/active-grants", params={"user_id": 6}, headers=alice).status_code == 403
    assert len(client.get("/active-grants", headers=auth(GRACE)).json()) == 1


def test_dev_token_disabled_in_oidc_mode(client, monkeypatch):
    monkeypatch.setattr("app.config.settings", type("S", (), {"auth_mode": "oidc"})())
    assert client.post("/auth/dev-token", json={"email": ALICE}).status_code == 404


def test_oidc_mode_verifies_rs256_against_jwks(client, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    import app.auth as auth_mod

    idp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://idp.aegis.example/realms/corp"

    class FakeJWKS:
        def get_signing_key_from_jwt(self, token):
            return type("K", (), {"key": idp_key.public_key()})()

    monkeypatch.setattr(auth_mod, "settings", _OidcSettings(issuer))
    monkeypatch.setattr(auth_mod, "_jwks_client", lambda: FakeJWKS())

    now = utcnow()
    claims = {
        "iss": issuer,
        "aud": "aegis-jit",
        "sub": "idp-123",
        "email": ALICE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    good = jwt.encode(claims, idp_key, algorithm="RS256")
    forged = jwt.encode(claims, attacker_key, algorithm="RS256")
    hs256 = jwt.encode(claims, "x" * 32, algorithm="HS256")  # algorithm-confusion attempt

    assert client.get("/me", headers={"Authorization": f"Bearer {good}"}).json()["email"] == ALICE
    assert client.get("/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    assert client.get("/me", headers={"Authorization": f"Bearer {hs256}"}).status_code == 401


class _OidcSettings:
    auth_mode = "oidc"
    oidc_audience = "aegis-jit"

    def __init__(self, issuer):
        self.oidc_issuer = issuer
