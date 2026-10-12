"""Signed audit checkpoints: catch deletion of the newest audit entries.

The HMAC chain catches an edit anywhere in the log, but someone who can write to the database
can delete the newest N entries and leave a shorter chain that still verifies. A checkpoint is
a signed statement, "the log had N entries, ending at entry #id with hash h", appended to a
file outside the database (``AEGIS_CHECKPOINT_FILE``). Verification checks each checkpoint's
Ed25519 signature and that the database still holds what it vouches for, so truncating the
log, or rewriting it with the HMAC key, no longer goes unnoticed.

Signing uses its own key (``AEGIS_CHECKPOINT_KEY``), separate from the HMAC key, and the
public key is published (``GET /audit-logs/checkpoints``) so anyone can check checkpoints
without being able to forge them. Checkpoints are also linked to each other by hash, so
removing one from the middle of the file shows too. In production, ship the file to
append-only storage (S3 Object Lock) or the SIEM, so the newest checkpoints can't be deleted
either.
"""

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import utcnow
from app.models import AuditLog

logger = logging.getLogger("aegis.checkpoints")
GENESIS = "0" * 64


@lru_cache(maxsize=1)
def _private_key() -> Ed25519PrivateKey:
    if settings.checkpoint_key:
        seed = base64.b64decode(settings.checkpoint_key)
    else:
        # Development fallback, derived so it survives restarts. With it, whoever holds the
        # HMAC key can also sign checkpoints; set AEGIS_CHECKPOINT_KEY in any real deployment.
        logger.warning("AEGIS_CHECKPOINT_KEY is not set; deriving a development checkpoint key")
        seed = hashlib.sha256(b"aegis-checkpoint-key:" + settings.audit_key.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key() -> Ed25519PublicKey:
    return _private_key().public_key()


def public_key_b64() -> str:
    raw = public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def key_id() -> str:
    return hashlib.sha256(base64.b64decode(public_key_b64())).hexdigest()[:16]


def _path() -> Path:
    return Path(settings.checkpoint_file)


def _canonical(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def _digest(checkpoint: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(checkpoint)).hexdigest()


def read_all() -> list[dict[str, Any]]:
    path = _path()
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def clear() -> None:
    """Forget all checkpoints. Only for wiping the whole database (seed --reset, demo reset)."""
    _path().unlink(missing_ok=True)


def create(db: Session) -> dict[str, Any] | None:
    """Sign and append a checkpoint for the current head of the log (None if the log is empty).
    Returns the latest checkpoint unchanged if nothing was logged since."""
    head = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    if head is None:
        return None
    existing = read_all()
    if existing and existing[-1]["head_id"] == head.id:
        return existing[-1]
    fields = {
        "seq": len(existing) + 1,
        "head_id": head.id,
        "head_hash": head.hash,
        "entries": db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.id <= head.id)),
        "created_at": utcnow().isoformat(timespec="seconds") + "Z",
        "prev": _digest(existing[-1]) if existing else GENESIS,
        "key_id": key_id(),
    }
    checkpoint = {**fields, "signature": base64.b64encode(_private_key().sign(_canonical(fields))).decode()}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(checkpoint, sort_keys=True) + "\n")
    logger.info("audit checkpoint %s: %s entries, head #%s", fields["seq"], fields["entries"], head.id)
    return checkpoint


def create_now() -> None:
    """Scheduler job."""
    from app.database import SessionLocal

    with SessionLocal() as db:
        create(db)


@dataclass
class CheckpointVerification:
    valid: bool
    checked: int
    first_invalid_seq: int | None = None
    missing_entry_id: int | None = None
    reason: str | None = None


def _problem(db: Session, cp: dict[str, Any], position: int, prev: str) -> tuple[str, int | None] | None:
    """Why checkpoint number ``position`` doesn't hold, with the missing entry id if any."""
    fields = {k: v for k, v in cp.items() if k != "signature"}
    seq = cp.get("seq", position)
    try:
        public_key().verify(base64.b64decode(cp.get("signature", "")), _canonical(fields))
    except (InvalidSignature, ValueError):
        return f"checkpoint {seq} has an invalid signature", None
    if seq != position or cp["prev"] != prev:
        return f"checkpoint {seq} doesn't follow checkpoint {position - 1}: one was removed or reordered", None
    entry = db.get(AuditLog, cp["head_id"])
    if entry is None:
        return (
            f"signed checkpoint {seq} vouches for {cp['entries']} entries ending at #{cp['head_id']}, "
            "which is no longer in the log: entries were deleted",
            cp["head_id"],
        )
    if entry.hash != cp["head_hash"]:
        return f"entry #{cp['head_id']} no longer matches signed checkpoint {seq}: the log was rewritten", None
    count = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.id <= cp["head_id"]))
    if count != cp["entries"]:
        return f"checkpoint {seq} vouches for {cp['entries']} entries up to #{cp['head_id']}, found {count}", None
    return None


def verify(db: Session) -> CheckpointVerification:
    prev = GENESIS
    checkpoints = read_all()
    for position, cp in enumerate(checkpoints, start=1):
        problem = _problem(db, cp, position, prev)
        if problem:
            reason, missing = problem
            return CheckpointVerification(False, position, cp.get("seq", position), missing, reason)
        prev = _digest(cp)
    return CheckpointVerification(True, len(checkpoints))
