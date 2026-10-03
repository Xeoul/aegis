"""Multi-factor step-up: RFC 6238 TOTP, and freshness checks on a token's MFA claims.

Signing in is not enough for the riskiest actions. Requests for restricted resources,
break-glass, and approving someone else's access all need a *recent* second factor, the
pattern OAuth calls step-up authentication (RFC 9470). When it's missing, Aegis answers 401
with ``WWW-Authenticate: Bearer error="insufficient_user_authentication"`` and the client
re-authenticates with MFA, then retries.

Where the second factor comes from depends on the auth mode:

* ``dev``: Aegis's stand-in issuer has its own TOTP authenticator (``/auth/mfa/enroll``,
  ``/auth/step-up``) and adds ``amr``, ``acr`` and ``auth_time`` to the token it issues.
* ``oidc``: the IdP does MFA. Its token counts as MFA when ``amr`` names a second factor or
  ``acr`` is one of ``AEGIS_OIDC_MFA_ACR``, and ``auth_time`` is recent.
"""

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from fastapi import HTTPException, status

from app.config import settings

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1  # accept the previous and next code too, for clock drift
MAX_FAILURES = 5  # consecutive wrong codes before the authenticator is locked
ACR_MFA = "urn:aegis:acr:mfa"
ISSUER = "Aegis-JIT"
# RFC 8176 authentication method references that mean a second factor was used.
MFA_AMR = {"mfa", "otp", "hwk", "swk", "fido", "sms", "face", "fpt"}


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _epoch(at: datetime) -> float:
    return (at if at.tzinfo else at.replace(tzinfo=UTC)).timestamp()


def step_at(at: datetime) -> int:
    return int(_epoch(at) // STEP_SECONDS)


def code_for_step(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def totp(secret: str, at: datetime) -> str:
    return code_for_step(secret, step_at(at))


def verify(secret: str, code: str, at: datetime, last_step: int | None) -> int | None:
    """The time step ``code`` belongs to, or None. A step at or before ``last_step`` was
    already used, so replaying a code (even within its 30 seconds) fails."""
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    now = step_at(at)
    for step in range(now - DRIFT_STEPS, now + DRIFT_STEPS + 1):
        if (last_step is None or step > last_step) and hmac.compare_digest(code_for_step(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, account: str) -> str:
    """The URI an authenticator app reads from a QR code."""
    label = quote(f"{ISSUER}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"


def is_fresh(claims: dict[str, Any], now: datetime) -> bool:
    """Whether a verified token shows a second factor within ``AEGIS_MFA_MAX_AGE_MINUTES``."""
    amr = claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    acr = claims.get("acr")
    trusted_acr = {ACR_MFA} if settings.auth_mode == "dev" else set(settings.oidc_mfa_acr)
    if not (MFA_AMR & {str(a).lower() for a in amr} or (acr and acr in trusted_acr)):
        return False
    auth_time = claims.get("auth_time", claims.get("iat"))
    if not isinstance(auth_time, int | float):
        return False
    return 0 <= _epoch(now) - auth_time <= settings.mfa_max_age_minutes * 60


def step_up_required(detail: str) -> HTTPException:
    """RFC 9470's challenge: re-authenticate with MFA (no older than max_age), then retry."""
    challenge = (
        f'Bearer error="insufficient_user_authentication", error_description="{detail}", '
        f'acr_values="{ACR_MFA}", max_age={settings.mfa_max_age_minutes * 60}'
    )
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        {"error": "insufficient_user_authentication", "message": detail},
        headers={"WWW-Authenticate": challenge},
    )
