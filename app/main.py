"""FastAPI application entry point: lifecycle and router wiring."""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import siem
from app.config import settings
from app.database import init_db
from app.routers import access, approvals, audit, auth, governance, users
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
        scheduler = create_scheduler(settings.revocation_interval_seconds)
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
UI_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


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


app.mount("/ui", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="ui")


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


for module in (auth, users, access, approvals, audit, governance):
    app.include_router(module.router)
