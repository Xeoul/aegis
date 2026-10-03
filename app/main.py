"""FastAPI application entry point: lifecycle and router wiring."""

import logging
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import credentials, llm_parser, siem
from app import scheduler as scheduler_module
from app.config import settings
from app.database import init_db
from app.routers import access, approvals, audit, auth, governance, scim, users
from app.scheduler import create_scheduler

logging.basicConfig(level=os.getenv("AEGIS_LOG_LEVEL", "INFO"))
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    siem.configure()
    if settings.auth_mode == "dev":
        logger.warning(
            "AEGIS_AUTH_MODE=dev: POST /auth/dev-token issues tokens for any provisioned user. "
            "Use AEGIS_AUTH_MODE=oidc outside local development."
        )
    scheduler = None
    if settings.scheduler_enabled:
        scheduler = create_scheduler(
            settings.revocation_interval_seconds, settings.demo_reset_minutes if settings.demo_mode else None
        )
        scheduler.start()
    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="Aegis-JIT",
    description="Just-In-Time IAM policy engine: natural-language access requests, ABAC evaluation, "
    "human approval for high-risk access, and auto-expiring grants.",
    version="0.3.0",
    lifespan=lifespan,
)


# The dashboard loads only same-origin files, so it can run under a strict CSP. Swagger UI at
# /docs pulls assets from a CDN, so the CSP is scoped to /ui.
def _ui_csp() -> str:
    # In oidc mode the dashboard talks to the IdP directly (discovery and the PKCE token
    # exchange), so its origin is the one addition to connect-src.
    connect = "'self'"
    if settings.auth_mode == "oidc":
        issuer = urlsplit(settings.oidc_issuer)
        connect += f" {issuer.scheme}://{issuer.netloc}"
    return (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        f"connect-src {connect}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )


UI_CSP = _ui_csp()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith("/ui"):
        response.headers["Content-Security-Policy"] = UI_CSP
    return response


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui/")


STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.is_dir():  # absent in the in-browser demo, which ships only the Python
    app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/meta", tags=["meta"])
def meta() -> dict[str, object]:
    """Public deployment facts the dashboard shows (no secrets)."""
    next_reset = None
    if settings.demo_mode and scheduler_module.last_demo_reset is not None:
        next_reset = scheduler_module.last_demo_reset + timedelta(minutes=settings.demo_reset_minutes)
    return {
        "demo_mode": settings.demo_mode,
        "auth_mode": settings.auth_mode,
        "parser": llm_parser.active_backend(),
        "credential_broker": "aws" if credentials.enabled() else "none",
        "demo_reset_minutes": settings.demo_reset_minutes if settings.demo_mode else None,
        "next_reset_at": next_reset.isoformat() if next_reset else None,
        "scim": bool(os.getenv("AEGIS_SCIM_TOKEN")),
        "oidc": {"issuer": settings.oidc_issuer, "client_id": settings.oidc_client_id}
        if settings.auth_mode == "oidc"
        else None,
    }


for module in (auth, users, access, approvals, audit, governance, scim):
    app.include_router(module.router)
app.add_exception_handler(scim.ScimError, scim.error_response)
