"""Bearer-token authentication and authorization helpers.

Identity always comes from a verified JWT, never from the request body. Tokens are mapped to
local users by their ``email`` claim, so the same code path serves the built-in development
issuer and any external OIDC provider.
"""

import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import mfa
from app.config import settings
from app.database import get_db, utcnow
from app.models import User

DEV_ISSUER = "aegis-jit-dev"
DEV_AUDIENCE = "aegis-jit"

# Job roles that may read the full audit trail and all grants (oversight functions).
OVERSIGHT_ROLES = {"auditor", "security engineer"}

_bearer = HTTPBearer(auto_error=False)


def create_dev_token(user: User, *, mfa_at: datetime | None = None) -> tuple[str, int]:
    """A token from the stand-in issuer. ``mfa_at`` marks a completed TOTP step-up, using the
    same claims an IdP would: ``amr`` (RFC 8176), ``acr`` and ``auth_time``."""
    ttl = settings.token_ttl_minutes * 60
    now = utcnow()
    claims: dict[str, Any] = {
        "iss": DEV_ISSUER,
        "aud": DEV_AUDIENCE,
        "sub": str(user.id),
        "email": user.email,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=ttl),
        "jti": uuid.uuid4().hex,
    }
    if mfa_at is not None:
        claims.update(amr=["pwd", "otp", "mfa"], acr=mfa.ACR_MFA, auth_time=int(mfa_at.replace(tzinfo=UTC).timestamp()))
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256"), ttl


@lru_cache(maxsize=1)
def _jwks_client() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(settings.oidc_jwks_url, cache_keys=True)


def _decode(token: str) -> dict[str, Any]:
    options: Any = {"require": ["exp", "iat", "iss", "aud"]}
    if settings.auth_mode == "oidc":
        key = _jwks_client().get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options=options,
        )
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=["HS256"],
        audience=DEV_AUDIENCE,
        issuer=DEV_ISSUER,
        options=options,
    )


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise _unauthorized("Missing bearer token")
    try:
        claims = _decode(credentials.credentials)
    except jwt.PyJWTError as exc:
        raise _unauthorized(f"Invalid token: {exc}") from exc

    email = claims.get("email")
    if not email:
        raise _unauthorized("Token has no email claim")
    user = db.scalar(select(User).where(User.email == email.lower()))
    if user is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authenticated identity is not provisioned in Aegis")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User account is deactivated")
    request.state.mfa = mfa.is_fresh(claims, utcnow())
    return user


def has_fresh_mfa(request: Request) -> bool:
    """Whether this request's token carries a recent second factor (after get_current_user)."""
    return bool(getattr(request.state, "mfa", False))


def is_oversight(user: User) -> bool:
    return user.is_admin or user.role.strip().lower() in OVERSIGHT_ROLES


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator privileges required")
    return user


def require_oversight(user: User = Depends(get_current_user)) -> User:
    if not is_oversight(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Auditor, security or administrator role required")
    return user
