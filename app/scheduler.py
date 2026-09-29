"""Background jobs: revoke expired grants and expire approvals nobody acted on."""

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from app import audit, credentials, workflow
from app.database import SessionLocal, utcnow
from app.models import AccessRequest, AuditEvent, RequestStatus, Resource

logger = logging.getLogger(__name__)

SWEEP_JOB_ID = "lifecycle-sweep"


def revoke_expired_grants() -> int:
    """Mark every ACTIVE grant whose ``expires_at`` has passed as REVOKED. Returns the count."""
    with SessionLocal() as db:
        expired = db.scalars(
            select(AccessRequest).where(
                AccessRequest.status == RequestStatus.ACTIVE,
                AccessRequest.expires_at <= utcnow(),
            )
        ).all()
        for grant in expired:
            assert grant.expires_at is not None  # guaranteed by the query
            workflow.revoke(
                db,
                grant,
                None,
                f"Grant expired at {grant.expires_at.isoformat()}Z and was automatically revoked.",
                early=False,
            )
        audit.commit(db)
    if expired:
        logger.info("Revoked %d expired grant(s)", len(expired))
    return len(expired)


def expire_stale_requests() -> int:
    """Close PENDING_APPROVAL requests whose approval window has passed. Returns the count."""
    with SessionLocal() as db:
        stale = db.scalars(
            select(AccessRequest).where(
                AccessRequest.status == RequestStatus.PENDING_APPROVAL,
                AccessRequest.approval_deadline <= utcnow(),
            )
        ).all()
        for req in stale:
            req.status = RequestStatus.EXPIRED
            audit.record(
                db,
                AuditEvent.REQUEST_EXPIRED,
                request_id=req.id,
                user_id=req.user_id,
                resource=req.resource,
                action=req.action,
                detail="No approver acted before the approval deadline.",
            )
        audit.commit(db)
    return len(stale)


def prune_cloud_revocations() -> int:
    """Remove AWS deny statements whose sessions have all expired."""
    if not credentials.enabled():
        return 0
    with SessionLocal() as db:
        roles = set(db.scalars(select(Resource.aws_role_arn).where(Resource.aws_role_arn.is_not(None))))
    removed = 0
    for role_arn in roles:
        try:
            removed += credentials.prune_revocations(role_arn)
        except Exception:  # noqa: BLE001 - keep sweeping other roles
            logger.exception("Could not prune revocations on %s", role_arn)
    return removed


def run_sweep() -> None:
    revoke_expired_grants()
    expire_stale_requests()
    prune_cloud_revocations()


def create_scheduler(interval_seconds: int = 60) -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        run_sweep,
        "interval",
        seconds=interval_seconds,
        id=SWEEP_JOB_ID,
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(timezone.utc),  # also sweep once at startup
    )
    return scheduler
