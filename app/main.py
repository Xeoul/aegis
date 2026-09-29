"""FastAPI application entry point: lifecycle and router wiring."""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.database import init_db
from app import siem
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


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


for module in (auth, users, access, approvals, audit, governance):
    app.include_router(module.router)
