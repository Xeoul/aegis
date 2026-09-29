"""Tamper-evident, append-only audit trail.

Each entry stores ``prev_hash`` and ``hash = HMAC-SHA256(key, prev_hash || canonical(entry))``.
Editing, deleting or reordering any row breaks every hash after it, and without the key
(kept outside the database) an attacker cannot forge a consistent replacement chain.
``prev_hash`` is UNIQUE, so two writers can never fork the chain: the second commit fails.
"""

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import siem
from app.config import settings
from app.database import utcnow
from app.models import AuditEvent, AuditLog

GENESIS_HASH = "0" * 64
_PENDING_KEY = "aegis_pending_audit"
_chain_lock = threading.Lock()


def record(
    db: Session,
    event: AuditEvent,
    *,
    detail: str = "",
    request_id: int | None = None,
    user_id: int | None = None,
    actor_id: int | None = None,
    resource: str | None = None,
    action: str | None = None,
) -> None:
    """Queue an audit entry; it is chained and written by :func:`commit`.

    Flush the session first if ``request_id`` refers to a row created in this transaction.
    """
    db.info.setdefault(_PENDING_KEY, []).append(
        dict(
            event=event,
            detail=detail,
            request_id=request_id,
            user_id=user_id,
            actor_id=actor_id,
            resource=resource,
            action=action,
        )
    )


def commit(db: Session) -> None:
    """Commit the session together with any queued audit entries, chained in order."""
    pending: list[dict[str, Any]] = db.info.pop(_PENDING_KEY, [])
    if not pending:
        db.commit()
        return
    written = []
    with _chain_lock:
        prev = db.scalar(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)) or GENESIS_HASH
        for fields in pending:
            entry = AuditLog(timestamp=utcnow(), prev_hash=prev, **fields)
            entry.hash = compute_hash(prev, entry)
            db.add(entry)
            written.append(entry)
            prev = entry.hash
        db.commit()
    siem.emit(written)  # only after the commit, so the SIEM never sees events that rolled back


def _canonical(entry: AuditLog) -> bytes:
    payload = {
        "timestamp": entry.timestamp.isoformat(),
        "event": AuditEvent(entry.event).value,
        "request_id": entry.request_id,
        "user_id": entry.user_id,
        "actor_id": entry.actor_id,
        "resource": entry.resource,
        "action": entry.action,
        "detail": entry.detail,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def compute_hash(prev_hash: str, entry: AuditLog) -> str:
    return hmac.new(settings.audit_key.encode(), prev_hash.encode() + _canonical(entry), hashlib.sha256).hexdigest()


@dataclass
class ChainVerification:
    valid: bool
    entries_checked: int
    head_hash: str
    first_invalid_id: int | None = None
    reason: str | None = None


def verify_chain(db: Session) -> ChainVerification:
    prev = GENESIS_HASH
    count = 0
    for entry in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        count += 1
        if entry.prev_hash != prev:
            return ChainVerification(False, count, prev, entry.id, "prev_hash does not match the preceding entry")
        if not hmac.compare_digest(entry.hash, compute_hash(prev, entry)):
            return ChainVerification(False, count, prev, entry.id, "entry contents do not match its hash")
        prev = entry.hash
    return ChainVerification(True, count, prev)
