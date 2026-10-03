from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, checkpoints
from app.auth import require_oversight
from app.database import get_db
from app.models import AuditEvent, AuditLog, User
from app.schemas import AuditLogOut, AuditVerificationOut, CheckpointOut, CheckpointsOut

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
    """Recompute the HMAC chain over the whole audit trail and report the first broken link, then
    check that every signed checkpoint still matches (which catches deleting the newest entries)."""
    chain = audit.verify_chain(db)
    if not chain.valid:
        return AuditVerificationOut(**chain.__dict__)
    signed = checkpoints.verify(db)
    return AuditVerificationOut(
        valid=signed.valid,
        entries_checked=chain.entries_checked,
        head_hash=chain.head_hash,
        first_invalid_id=signed.missing_entry_id,
        reason=signed.reason,
        checkpoints_checked=signed.checked,
    )


@router.get("/audit-logs/checkpoints", response_model=CheckpointsOut, dependencies=[Depends(require_oversight)])
def list_checkpoints() -> CheckpointsOut:
    return CheckpointsOut(
        public_key=checkpoints.public_key_b64(),
        key_id=checkpoints.key_id(),
        checkpoints=[CheckpointOut(**cp) for cp in checkpoints.read_all()],
    )


@router.post("/audit-logs/checkpoints", response_model=CheckpointOut | None, dependencies=[Depends(require_oversight)])
def create_checkpoint(db: Session = Depends(get_db)) -> CheckpointOut | None:
    """Sign a checkpoint now (the scheduler also does it every AEGIS_CHECKPOINT_INTERVAL_MINUTES)."""
    checkpoint = checkpoints.create(db)
    return CheckpointOut(**checkpoint) if checkpoint else None
