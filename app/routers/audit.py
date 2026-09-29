from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.auth import require_oversight
from app.database import get_db
from app.models import AuditEvent, AuditLog, User
from app.schemas import AuditLogOut, AuditVerificationOut

router = APIRouter(tags=["audit"])


@router.get("/audit-logs", response_model=list[AuditLogOut])
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


@router.get("/audit-logs/verify", response_model=AuditVerificationOut)
def verify_audit_logs(_: User = Depends(require_oversight), db: Session = Depends(get_db)) -> AuditVerificationOut:
    """Recompute the HMAC chain over the whole audit trail and report the first broken link."""
    return AuditVerificationOut(**audit.verify_chain(db).__dict__)
