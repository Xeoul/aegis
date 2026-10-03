"""Runtime configuration, read once from environment variables."""

import logging
import os
import secrets
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # "dev": Aegis issues its own HS256 tokens via POST /auth/dev-token (a stand-in IdP).
    # "oidc": tokens are issued by an external IdP (Keycloak, Okta, Entra ID, Auth0) and
    #         verified against its JWKS; the dev token endpoint is disabled.
    auth_mode: str = field(default_factory=lambda: os.getenv("AEGIS_AUTH_MODE", "dev").lower())
    jwt_secret: str = field(default_factory=lambda: os.getenv("AEGIS_JWT_SECRET", ""))
    token_ttl_minutes: int = field(default_factory=lambda: int(os.getenv("AEGIS_TOKEN_TTL_MINUTES", "60")))
    oidc_issuer: str = field(default_factory=lambda: os.getenv("AEGIS_OIDC_ISSUER", ""))
    oidc_audience: str = field(default_factory=lambda: os.getenv("AEGIS_OIDC_AUDIENCE", "aegis-jit"))
    oidc_jwks_url: str = field(default_factory=lambda: os.getenv("AEGIS_OIDC_JWKS_URL", ""))
    # IdP "acr" values that count as multi-factor (amr values such as "mfa" or "otp" always do).
    oidc_mfa_acr: tuple[str, ...] = field(
        default_factory=lambda: tuple(v.strip() for v in os.getenv("AEGIS_OIDC_MFA_ACR", "").split(",") if v.strip())
    )
    # How recent a second factor must be for step-up actions (restricted access, approvals).
    mfa_max_age_minutes: int = field(default_factory=lambda: int(os.getenv("AEGIS_MFA_MAX_AGE_MINUTES", "15")))
    # Key for the HMAC audit chain. Keep it outside the database so someone with only
    # database access cannot recompute the chain after editing history.
    audit_key: str = field(default_factory=lambda: os.getenv("AEGIS_AUDIT_KEY", ""))
    scheduler_enabled: bool = field(default_factory=lambda: _env_bool("AEGIS_SCHEDULER_ENABLED", True))
    # Public demo: shows a sandbox banner and periodically wipes and re-seeds the database so
    # every visitor starts from the same clean story.
    demo_mode: bool = field(default_factory=lambda: _env_bool("AEGIS_DEMO_MODE", False))
    demo_reset_minutes: int = field(default_factory=lambda: int(os.getenv("AEGIS_DEMO_RESET_MINUTES", "180")))
    revocation_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_REVOCATION_INTERVAL_SECONDS", "60"))
    )

    def __post_init__(self) -> None:
        if self.auth_mode not in {"dev", "oidc"}:
            raise ValueError(f"AEGIS_AUTH_MODE must be 'dev' or 'oidc', got {self.auth_mode!r}")
        if self.auth_mode == "oidc" and not (self.oidc_issuer and self.oidc_jwks_url):
            raise ValueError("AEGIS_AUTH_MODE=oidc requires AEGIS_OIDC_ISSUER and AEGIS_OIDC_JWKS_URL")
        if not self.jwt_secret:
            # A random per-process secret: dev tokens stop working after a restart, which is
            # safer than a well-known default.
            object.__setattr__(self, "jwt_secret", secrets.token_urlsafe(32))
        if not self.audit_key:
            logger.warning("AEGIS_AUDIT_KEY is not set; using an insecure development audit key")
            object.__setattr__(self, "audit_key", "aegis-insecure-dev-audit-key")


settings = Settings()
