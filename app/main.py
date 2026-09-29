"""FastAPI application: user management, JIT access requests, grants and audit history."""

import logging
import os
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db, init_db, utcnow
from app.evaluator import evaluate
from app.llm_parser import ParserError, parse_access_request
from app.models import AccessRequest, AuditEvent, AuditLog, RequestStatus, Resource, User
from app.scheduler import create_scheduler
from app.schemas import (
    ABACPolicy,
    AccessDecisionOut,
    AccessRequestIn,
    AuditLogOut,
    GrantOut,
    PolicyConditions,
    PolicyResource,
    PolicySubject,
    ResourceOut,
    UserCreate,
    UserOut,
)

logging.basicConfig(level=os.getenv("AEGIS_LOG_LEVEL", "INFO"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    scheduler = None
    if os.getenv("AEGIS_SCHEDULER_ENABLED", "true").lower() == "true":
        scheduler = create_scheduler(int(os.getenv("AEGIS_REVOCATION_INTERVAL_SECONDS", "60")))
        scheduler.start()
    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="Aegis-JIT",
    description="Just-In-Time IAM policy engine: natural-language access requests, ABAC evaluation, auto-expiring grants.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


# --- Users & resources -------------------------------------------------------


@app.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED, tags=["users"])
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    user = User(**payload.model_dump())
    db.add(user)
    db.commit()
    return user


@app.get("/users", response_model=list[UserOut], tags=["users"])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


@app.get("/resources", response_model=list[ResourceOut], tags=["resources"])
def list_resources(db: Session = Depends(get_db)) -> list[Resource]:
    return list(db.scalars(select(Resource).order_by(Resource.id)))


# --- Access requests ---------------------------------------------------------


@app.post("/request-access", response_model=AccessDecisionOut, tags=["access"])
def request_access(payload: AccessRequestIn, db: Session = Depends(get_db)) -> AccessDecisionOut:
    user = db.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"User {payload.user_id} not found")

    catalog = list(db.scalars(select(Resource.name)))
    try:
        parsed = parse_access_request(payload.request_text, catalog)
    except ParserError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    policy = parsed.policy

    resource = db.scalar(select(Resource).where(Resource.name == policy.resource))
    result = evaluate(user, resource, policy)

    now = utcnow()
    expires_at = now + timedelta(hours=result.granted_duration_hours) if result.allowed else None
    record = AccessRequest(
        user_id=user.id,
        resource=policy.resource,
        action=policy.action,
        status=RequestStatus.ACTIVE if result.allowed else RequestStatus.DENIED,
        created_at=now,
        expires_at=expires_at,
        request_text=payload.request_text,
        allow_reason=policy.allow_reason,
        duration_hours=result.granted_duration_hours,
        decision_reason=" ".join(result.reasons),
        parser=parsed.parser,
    )
    db.add(record)
    db.flush()

    audit_common = dict(request_id=record.id, user_id=user.id, resource=policy.resource, action=policy.action)
    db.add(
        AuditLog(
            event=AuditEvent.REQUEST_SUBMITTED,
            timestamp=now,
            detail=f'[{parsed.parser}] "{payload.request_text}"',
            **audit_common,
        )
    )
    db.add(
        AuditLog(
            event=AuditEvent.ACCESS_GRANTED if result.allowed else AuditEvent.ACCESS_DENIED,
            timestamp=now,
            detail=(
                f"Granted for {result.granted_duration_hours}h until {expires_at.isoformat()}Z. "
                if result.allowed
                else ""
            )
            + " ".join(result.reasons),
            **audit_common,
        )
    )
    db.commit()

    return AccessDecisionOut(
        request_id=record.id,
        decision=result.decision,
        status=record.status,
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
            conditions=PolicyConditions(duration_hours=result.granted_duration_hours, not_after=expires_at),
            justification=policy.allow_reason,
        ),
    )


@app.get("/active-grants", response_model=list[GrantOut], tags=["access"])
def active_grants(
    user_id: int | None = Query(None, description="Only grants for this user"),
    db: Session = Depends(get_db),
) -> list[AccessRequest]:
    # Filter on expires_at as well so a grant never shows as active between its expiry
    # and the next scheduler sweep.
    query = select(AccessRequest).where(
        AccessRequest.status == RequestStatus.ACTIVE,
        AccessRequest.expires_at > utcnow(),
    )
    if user_id is not None:
        query = query.where(AccessRequest.user_id == user_id)
    return list(db.scalars(query.order_by(AccessRequest.expires_at)))


@app.get("/audit-logs", response_model=list[AuditLogOut], tags=["audit"])
def audit_logs(
    user_id: int | None = Query(None),
    event: AuditEvent | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    query = select(AuditLog)
    if user_id is not None:
        query = query.where(AuditLog.user_id == user_id)
    if event is not None:
        query = query.where(AuditLog.event == event)
    return list(db.scalars(query.order_by(AuditLog.id.desc()).limit(limit)))
