from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, workflow
from app.auth import get_current_user, is_oversight
from app.database import get_db, utcnow
from app.evaluator import evaluate
from app.llm_parser import ParserError, parse_access_request
from app.models import AccessRequest, AuditEvent, RequestStatus, Resource, User
from app.schemas import (
    ABACPolicy,
    AccessDecisionOut,
    AccessRequestIn,
    GrantOut,
    PolicyConditions,
    PolicyResource,
    PolicySubject,
    RequestOut,
    RevokeIn,
)

router = APIRouter(tags=["access"])


def load_request(db: Session, request_id: int) -> tuple[AccessRequest, Resource | None]:
    req = db.get(AccessRequest, request_id)
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Request {request_id} not found")
    return req, db.scalar(select(Resource).where(Resource.name == req.resource))


@router.post("/request-access", response_model=AccessDecisionOut)
def request_access(
    payload: AccessRequestIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessDecisionOut:
    catalog = list(db.scalars(select(Resource.name)))
    try:
        parsed = parse_access_request(payload.request_text, catalog)
    except ParserError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    policy = parsed.policy

    resource = db.scalar(select(Resource).where(Resource.name == policy.resource))
    result = evaluate(user, resource, policy)

    record = AccessRequest(
        user_id=user.id,
        resource=policy.resource,
        action=policy.action,
        status=RequestStatus.DENIED,
        created_at=utcnow(),
        request_text=payload.request_text,
        allow_reason=policy.allow_reason,
        duration_hours=result.granted_duration_hours,
        decision_reason=" ".join(result.reasons),
        parser=parsed.parser,
    )
    db.add(record)
    db.flush()

    common = dict(request_id=record.id, user_id=user.id, actor_id=user.id, resource=policy.resource, action=policy.action)
    audit.record(db, AuditEvent.REQUEST_SUBMITTED, detail=f'[{parsed.parser}] "{payload.request_text}"', **common)
    if not result.allowed:
        audit.record(db, AuditEvent.ACCESS_DENIED, detail=" ".join(result.reasons), **common)
    elif result.requires_approval and payload.break_glass:
        workflow.break_glass(db, record, policy.allow_reason)
    elif result.requires_approval:
        workflow.start_approval(db, record)
    else:
        workflow.activate(db, record, user.id, " ".join(result.reasons))
    audit.commit(db)

    return AccessDecisionOut(
        request_id=record.id,
        decision=result.decision,
        status=record.status,
        requires_approval=result.requires_approval,
        break_glass=record.break_glass,
        approval_deadline=record.approval_deadline,
        reasons=result.reasons,
        parsed=policy,
        parser=parsed.parser,
        policy=ABACPolicy(
            effect=result.decision,
            subject=PolicySubject(user_id=user.id, role=user.role, department=user.department),
            resource=PolicyResource(
                name=policy.resource,
                sensitivity_level=resource.sensitivity_level if resource else None,
            ),
            action=policy.action,
            conditions=PolicyConditions(duration_hours=record.duration_hours, not_after=record.expires_at),
            justification=policy.allow_reason,
        ),
    )


@router.get("/requests", response_model=list[RequestOut])
def my_requests(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[AccessRequest]:
    """Every request you have submitted, newest first."""
    query = select(AccessRequest).where(AccessRequest.user_id == user.id).order_by(AccessRequest.id.desc())
    return list(db.scalars(query))


@router.get("/requests/{request_id}", response_model=RequestOut)
def get_request(request_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> AccessRequest:
    req, resource = load_request(db, request_id)
    if req.user_id != user.id and not is_oversight(user) and not workflow.approver_eligibility(user, req, resource)[0]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Request {request_id} not found")
    return req


@router.get("/active-grants", response_model=list[GrantOut])
def active_grants(
    user_id: int | None = Query(None, description="Only grants for this user (oversight roles only)"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AccessRequest]:
    """Your own active grants. Auditors, security engineers and admins see everyone's."""
    if not is_oversight(user):
        if user_id not in (None, user.id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only list your own grants")
        user_id = user.id
    # Filter on expires_at as well so a grant never shows as active between its expiry
    # and the next scheduler sweep.
    query = select(AccessRequest).where(
        AccessRequest.status == RequestStatus.ACTIVE,
        AccessRequest.expires_at > utcnow(),
    )
    if user_id is not None:
        query = query.where(AccessRequest.user_id == user_id)
    return list(db.scalars(query.order_by(AccessRequest.expires_at)))


@router.post("/grants/{grant_id}/revoke", response_model=RequestOut)
def revoke_grant(
    grant_id: int, payload: RevokeIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> AccessRequest:
    """End a grant early. Allowed for the grantee, eligible approvers, and security engineers."""
    grant, resource = load_request(db, grant_id)
    allowed = (
        grant.user_id == user.id
        or user.role.strip().lower() == "security engineer"
        or workflow.approver_eligibility(user, grant, resource)[0]
    )
    if not allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You may not revoke this grant")
    if grant.status != RequestStatus.ACTIVE:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Grant is {grant.status.value}, not ACTIVE")
    workflow.revoke(db, grant, user.id, f"Revoked early: {payload.reason}")
    audit.commit(db)
    return grant
