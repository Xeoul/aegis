from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app import audit, workflow
from app.auth import get_current_user
from app.database import get_db, utcnow
from app.evaluator import evaluate
from app.models import AccessRequest, AuditEvent, RequestStatus, Resource, User
from app.routers.access import load_request
from app.schemas import ApprovalTaskOut, CommentIn, ParsedPolicy, RequestOut

router = APIRouter(tags=["approvals"])


def _require_eligible(user: User, req: AccessRequest, resource: Resource | None) -> None:
    ok, reason = workflow.approver_eligibility(user, req, resource)
    if not ok:
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)


@router.get("/approvals", response_model=list[ApprovalTaskOut])
def approval_queue(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[ApprovalTaskOut]:
    """Pending requests you may approve and break-glass grants you may review."""
    candidates = db.scalars(
        select(AccessRequest)
        .where(
            or_(
                AccessRequest.status == RequestStatus.PENDING_APPROVAL,
                (AccessRequest.break_glass.is_(True)) & (AccessRequest.reviewed_at.is_(None)),
            )
        )
        .order_by(AccessRequest.id)
    ).all()
    resources = {r.name: r for r in db.scalars(select(Resource))}
    tasks = []
    for req in candidates:
        ok, reason = workflow.approver_eligibility(user, req, resources.get(req.resource))
        if ok:
            kind = "approval" if req.status == RequestStatus.PENDING_APPROVAL else "break_glass_review"
            tasks.append(ApprovalTaskOut(kind=kind, eligibility=reason, request=RequestOut.model_validate(req)))
    return tasks


def _pending(db: Session, request_id: int, user: User) -> tuple[AccessRequest, Resource | None]:
    req, resource = load_request(db, request_id)
    _require_eligible(user, req, resource)
    if req.status != RequestStatus.PENDING_APPROVAL:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Request is {req.status.value}, not PENDING_APPROVAL")
    if req.approval_deadline and req.approval_deadline <= utcnow():
        raise HTTPException(status.HTTP_409_CONFLICT, "The approval window for this request has closed")
    return req, resource


@router.post("/requests/{request_id}/approve", response_model=RequestOut)
def approve(
    request_id: int, payload: CommentIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> AccessRequest:
    req, resource = _pending(db, request_id, user)
    # Attributes may have changed since submission (role change, resource reclassified), so
    # the policy is evaluated again at approval time.
    recheck = evaluate(
        req.user,
        resource,
        ParsedPolicy(
            resource=req.resource, action=req.action, allow_reason=req.allow_reason, duration_hours=req.duration_hours
        ),
    )
    now = utcnow()
    req.decided_by_id, req.decided_at, req.decision_comment = user.id, now, payload.comment
    if not recheck.allowed:
        req.status = RequestStatus.DENIED
        req.decision_reason = " ".join(recheck.reasons)
        audit.record(
            db,
            AuditEvent.ACCESS_DENIED,
            request_id=req.id,
            user_id=req.user_id,
            actor_id=user.id,
            resource=req.resource,
            action=req.action,
            detail="Policy re-check at approval time failed: " + req.decision_reason,
        )
    else:
        req.duration_hours = recheck.granted_duration_hours
        audit.record(
            db,
            AuditEvent.REQUEST_APPROVED,
            request_id=req.id,
            user_id=req.user_id,
            actor_id=user.id,
            resource=req.resource,
            action=req.action,
            detail=payload.comment,
        )
        workflow.activate(db, req, user.id, f"Approved by user {user.id}.")
    audit.commit(db)
    return req


@router.post("/requests/{request_id}/reject", response_model=RequestOut)
def reject(
    request_id: int, payload: CommentIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> AccessRequest:
    req, _ = _pending(db, request_id, user)
    req.status = RequestStatus.REJECTED
    req.decided_by_id, req.decided_at, req.decision_comment = user.id, utcnow(), payload.comment
    audit.record(
        db,
        AuditEvent.REQUEST_REJECTED,
        request_id=req.id,
        user_id=req.user_id,
        actor_id=user.id,
        resource=req.resource,
        action=req.action,
        detail=payload.comment,
    )
    audit.commit(db)
    return req


@router.post("/requests/{request_id}/review", response_model=RequestOut)
def review_break_glass(
    request_id: int, payload: CommentIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> AccessRequest:
    """Post-incident review of a break-glass grant by an eligible approver."""
    req, resource = load_request(db, request_id)
    _require_eligible(user, req, resource)
    if not req.break_glass or req.reviewed_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Not an unreviewed break-glass grant")
    req.reviewed_by_id, req.reviewed_at = user.id, utcnow()
    audit.record(
        db,
        AuditEvent.BREAK_GLASS_REVIEWED,
        request_id=req.id,
        user_id=req.user_id,
        actor_id=user.id,
        resource=req.resource,
        action=req.action,
        detail=payload.comment,
    )
    audit.commit(db)
    return req
