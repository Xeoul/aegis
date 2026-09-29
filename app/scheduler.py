"""Background job that revokes expired just-in-time grants."""

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from app.database import SessionLocal, utcnow
from app.models import AccessRequest, AuditEvent, AuditLog, RequestStatus

logger = logging.getLogger(__name__)

REVOCATION_JOB_ID = "revoke-expired-grants"


def revoke_expired_grants() -> int:
    """Mark every ACTIVE grant whose ``expires_at`` has passed as REVOKED. Returns the count."""
    now = utcnow()
    with SessionLocal() as db:
        expired = db.scalars(
            select(AccessRequest).where(
                AccessRequest.status == RequestStatus.ACTIVE,
                AccessRequest.expires_at <= now,
            )
        ).all()
        for grant in expired:
            grant.status = RequestStatus.REVOKED
            grant.revoked_at = now
            db.add(
                AuditLog(
                    event=AuditEvent.ACCESS_REVOKED,
                    request_id=grant.id,
                    user_id=grant.user_id,
                    resource=grant.resource,
                    action=grant.action,
                    detail=f"Grant expired at {grant.expires_at.isoformat()}Z and was automatically revoked.",
                )
            )
        db.commit()
    if expired:
        logger.info("Revoked %d expired grant(s)", len(expired))
    return len(expired)


def create_scheduler(interval_seconds: int = 60) -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        revoke_expired_grants,
        "interval",
        seconds=interval_seconds,
        id=REVOCATION_JOB_ID,
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(timezone.utc),  # also sweep once at startup
    )
    return scheduler

