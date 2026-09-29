"""FastAPI application: identities, JIT access requests, grants and audit history."""

import logging
import os
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.auth import create_dev_token, get_current_user, is_oversight, require_admin, require_oversight
from app.config import settings
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
    AuditVerificationOut,
    DevTokenRequest,
    GrantOut,
    PolicyConditions,
    PolicyResource,
    PolicySubject,
    ResourceOut,
    TokenOut,
    UserCreate,
    UserOut,
)

logging.basicConfig(level=os.getenv("AEGIS_LOG_LEVEL", "INFO"))
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
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
    description="Just-In-Time IAM policy engine: natural-language access requests, ABAC evaluation, auto-expiring grants.",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


# --- Authentication ------------------------------------------------------------


@app.post("/auth/dev-token", response_model=TokenOut, tags=["auth"])
def dev_token(payload: DevTokenRequest, db: Session = Depends(get_db)) -> TokenOut:
    """Stand-in identity provider for local development. Disabled when AEGIS_AUTH_MODE=oidc."""
    if settings.auth_mode != "dev":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or inactive user")
    token, ttl = create_dev_token(user)
    return TokenOut(access_token=token, expires_in=ttl)


@app.get("/me", response_model=UserOut, tags=["auth"])
def me(user: User = Depends(get_current_user)) -> User:
    return user


# --- Users & resources -------------------------------------------------------


@app.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED, tags=["users"])
def create_user(payload: UserCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)) -> User:
    user = User(**payload.model_dump())
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, f"A user with email {payload.email} already exists") from exc
    audit.record(
        db,
        AuditEvent.USER_CREATED,
        user_id=user.id,
        actor_id=admin.id,
        detail=f"Provisioned {user.email} ({user.department}/{user.role}, admin={user.is_admin}).",
    )
    audit.commit(db)
    return user


@app.get("/users", response_model=list[UserOut], tags=["users"])
def list_users(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


@app.get("/resources", response_model=list[ResourceOut], tags=["resources"])
def list_resources(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Resource]:
    return list(db.scalars(select(Resource).order_by(Resource.id)))


# --- Access requests ---------------------------------------------------------


@app.post("/request-access", response_model=AccessDecisionOut, tags=["access"])
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

    common = dict(request_id=record.id, user_id=user.id, actor_id=user.id, resource=policy.resource, action=policy.action)
    audit.record(db, AuditEvent.REQUEST_SUBMITTED, detail=f'[{parsed.parser}] "{payload.request_text}"', **common)
    if result.allowed and expires_at is not None:
        detail = f"Granted for {result.granted_duration_hours}h until {expires_at.isoformat()}Z. "
        audit.record(db, AuditEvent.ACCESS_GRANTED, detail=detail + " ".join(result.reasons), **common)
    else:
        audit.record(db, AuditEvent.ACCESS_DENIED, detail=" ".join(result.reasons), **common)
    audit.commit(db)

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


# --- Audit -------------------------------------------------------------------


@app.get("/audit-logs", response_model=list[AuditLogOut], tags=["audit"])
def audit_logs(
    user_id: int | None = Query(None),
    event: AuditEvent | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    _: User = Depends(require_oversight),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    query = select(AuditLog)
    if user_id is not None:
        query = query.where(AuditLog.user_id == user_id)
    if event is not None:
        query = query.where(AuditLog.event == event)
    return list(db.scalars(query.order_by(AuditLog.id.desc()).limit(limit)))


@app.get("/audit-logs/verify", response_model=AuditVerificationOut, tags=["audit"])
def verify_audit_logs(_: User = Depends(require_oversight), db: Session = Depends(get_db)) -> AuditVerificationOut:
    """Recompute the HMAC chain over the whole audit trail and report the first broken link."""
    return AuditVerificationOut(**audit.verify_chain(db).__dict__)
