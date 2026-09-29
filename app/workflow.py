"""Grant lifecycle: approvals, separation of duties, break-glass, revocation, leavers/movers."""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

import logging

from app import audit, credentials
from app.database import utcnow
from app.evaluator import BREAK_GLASS_MAX_HOURS, normalize
from app.models import AccessRequest, AuditEvent, RequestStatus, Resource, User

logger = logging.getLogger(__name__)

APPROVAL_WINDOW_HOURS = 24

# Security engineers may approve anywhere. Managers approve for their own reports and for
# resources their department owns. Identity administrators are deliberately NOT approvers:
# whoever manages accounts should not also be able to hand out access.
GLOBAL_APPROVER_ROLES = {"security engineer"}
DEPARTMENT_APPROVER_ROLES = {"manager"}


def approver_eligibility(approver: User, request: AccessRequest, resource: Resource | None) -> tuple[bool, str]:
    """Can ``approver`` approve, reject or review ``request``? Returns (allowed, reason)."""
    if approver.id == request.user_id:
        return False, "Separation of duties: you cannot approve your own request."
    if not approver.is_active:
        return False, "Approver account is deactivated."
    role = normalize(approver.role)
    if role in GLOBAL_APPROVER_ROLES:
        return True, f"{approver.role} may approve any request."
    if request.user.manager_id == approver.id:
        return True, "Approver is the requester's manager."
    if (
        role in DEPARTMENT_APPROVER_ROLES
        and resource is not None
        and resource.owner_department
        and normalize(approver.department) == normalize(resource.owner_department)
    ):
        return True, f"Approver manages {resource.owner_department}, which owns {resource.name}."
    return False, "Only the requester's manager, a manager of the owning department, or security may approve."


def activate(db: Session, request: AccessRequest, actor_id: int | None, detail: str) -> None:
    now = utcnow()
    request.status = RequestStatus.ACTIVE
    request.expires_at = now + timedelta(hours=request.duration_hours)
    audit.record(
        db,
        AuditEvent.ACCESS_GRANTED,
        request_id=request.id,
        user_id=request.user_id,
        actor_id=actor_id,
        resource=request.resource,
        action=request.action,
        detail=f"Granted for {request.duration_hours}h until {request.expires_at.isoformat()}Z. {detail}".strip(),
    )


def start_approval(db: Session, request: AccessRequest) -> None:
    request.status = RequestStatus.PENDING_APPROVAL
    request.approval_deadline = utcnow() + timedelta(hours=APPROVAL_WINDOW_HOURS)
    audit.record(
        db,
        AuditEvent.APPROVAL_REQUIRED,
        request_id=request.id,
        user_id=request.user_id,
        actor_id=request.user_id,
        resource=request.resource,
        action=request.action,
        detail=f"Awaiting approval until {request.approval_deadline.isoformat()}Z.",
    )


def break_glass(db: Session, request: AccessRequest, reason: str) -> None:
    request.break_glass = True
    request.duration_hours = min(request.duration_hours, BREAK_GLASS_MAX_HOURS)
    audit.record(
        db,
        AuditEvent.BREAK_GLASS_USED,
        request_id=request.id,
        user_id=request.user_id,
        actor_id=request.user_id,
        resource=request.resource,
        action=request.action,
        detail=f"Emergency access without prior approval, capped at {request.duration_hours}h. "
        f"Requires post-incident review. Justification: {reason}",
    )
    activate(db, request, request.user_id, "Break-glass.")


def revoke(db: Session, grant: AccessRequest, actor_id: int | None, reason: str, *, early: bool = True) -> None:
    """End a grant. ``early`` means before its natural expiry, so any cloud sessions issued for it
    must be actively invalidated. On natural expiry the STS credentials expire by themselves."""
    now = utcnow()
    grant.status = RequestStatus.REVOKED
    grant.revoked_at = now
    grant.revoked_by_id = actor_id
    grant.revoke_reason = reason
    audit.record(
        db,
        AuditEvent.ACCESS_REVOKED,
        request_id=grant.id,
        user_id=grant.user_id,
        actor_id=actor_id,
        resource=grant.resource,
        action=grant.action,
        detail=reason,
    )
    if early and grant.credentials_issued_at is not None:
        _revoke_cloud_sessions(db, grant, actor_id)


def _revoke_cloud_sessions(db: Session, grant: AccessRequest, actor_id: int | None) -> None:
    resource = db.scalar(select(Resource).where(Resource.name == grant.resource))
    if resource is None or not resource.aws_role_arn:
        return
    common = dict(request_id=grant.id, user_id=grant.user_id, actor_id=actor_id, resource=grant.resource, action=grant.action)
    try:
        credentials.revoke_sessions(grant, resource)
    except Exception as exc:  # noqa: BLE001 - any AWS failure must be surfaced, not swallowed
        logger.exception("Failed to revoke AWS sessions for grant %s", grant.id)
        audit.record(
            db,
            AuditEvent.CLOUD_REVOCATION_FAILED,
            detail=f"Could not deny sessions on {resource.aws_role_arn}: {exc}. Manual action required.",
            **common,
        )
        return
    audit.record(
        db,
        AuditEvent.CLOUD_SESSIONS_REVOKED,
        detail=f"Denied sessions '{credentials.session_name(grant)}' on {resource.aws_role_arn}.",
        **common,
    )


def revoke_all_for_user(db: Session, user: User, actor_id: int | None, reason: str) -> int:
    """Revoke active grants and cancel pending requests (used for leavers and movers)."""
    open_requests = db.scalars(
        select(AccessRequest).where(
            AccessRequest.user_id == user.id,
            AccessRequest.status.in_([RequestStatus.ACTIVE, RequestStatus.PENDING_APPROVAL]),
        )
    ).all()
    for req in open_requests:
        if req.status == RequestStatus.ACTIVE:
            revoke(db, req, actor_id, reason)
        else:
            req.status = RequestStatus.REJECTED
            req.decided_by_id = actor_id
            req.decided_at = utcnow()
            req.decision_comment = reason
            audit.record(
                db,
                AuditEvent.REQUEST_REJECTED,
                request_id=req.id,
                user_id=req.user_id,
                actor_id=actor_id,
                resource=req.resource,
                action=req.action,
                detail=reason,
            )
    return len(open_requests)
