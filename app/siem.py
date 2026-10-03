"""Export audit events in an OCSF-style JSON shape for SIEM ingestion (Splunk, Elastic, Sentinel).

Two delivery paths:

* **Push.** Every committed audit entry is written as one JSON line to the ``aegis.siem`` logger.
  Set ``AEGIS_SIEM_LOG_FILE`` to a path (for a Splunk UF / Filebeat / Fluent Bit tail) or to
  ``stdout`` (for container log shipping).
* **Pull.** ``GET /audit-logs/export?after_id=N`` returns NDJSON, with the id as the cursor.

The field names follow the Open Cybersecurity Schema Framework (class, category, activity,
severity, actor, user, resources, metadata) closely enough to map with little effort. Aegis
specifics go in ``unmapped``. The chain hash goes in ``metadata.uid``, so the SIEM copy can be
checked against the source.
"""

import json
import logging
import os
import sys
from datetime import UTC
from typing import Any

from app.models import AuditEvent, AuditLog

logger = logging.getLogger("aegis.siem")
logger.propagate = False

PRODUCT = {"name": "Aegis-JIT", "vendor_name": "aegis-jit", "version": "0.5.0"}

# OCSF class per event: 3001 Account Change, 3003 Authorize Session, 2004 Detection Finding.
_ACCOUNT_CHANGE = (3001, "Account Change", 3, "Identity & Access Management")
_AUTHORIZE = (3003, "Authorize Session", 3, "Identity & Access Management")
_FINDING = (2004, "Detection Finding", 2, "Findings")
_AUTHENTICATION = (3002, "Authentication", 3, "Identity & Access Management")

_EVENT_CLASS = {
    AuditEvent.USER_CREATED: _ACCOUNT_CHANGE,
    AuditEvent.USER_UPDATED: _ACCOUNT_CHANGE,
    AuditEvent.USER_DEACTIVATED: _ACCOUNT_CHANGE,
    AuditEvent.MFA_ENROLLED: _ACCOUNT_CHANGE,
    AuditEvent.MFA_RESET: _ACCOUNT_CHANGE,
    AuditEvent.MFA_VERIFIED: _AUTHENTICATION,
    AuditEvent.MFA_FAILED: _AUTHENTICATION,
    AuditEvent.ALERT_RAISED: _FINDING,
    AuditEvent.ALERT_RESOLVED: _FINDING,
}
_FAILURES = {
    AuditEvent.MFA_FAILED,
    AuditEvent.STEP_UP_REQUIRED,
    AuditEvent.ACCESS_DENIED,
    AuditEvent.REQUEST_REJECTED,
    AuditEvent.CLOUD_REVOCATION_FAILED,
}
# OCSF severity_id: 1 informational, 2 low, 3 medium, 4 high.
_SEVERITY = {
    AuditEvent.ACCESS_DENIED: 2,
    AuditEvent.BREAK_GLASS_USED: 4,
    AuditEvent.CLOUD_REVOCATION_FAILED: 4,
    AuditEvent.ALERT_RAISED: 3,
    AuditEvent.USER_DEACTIVATED: 2,
    AuditEvent.MFA_FAILED: 3,
    AuditEvent.MFA_RESET: 3,
}


def to_ocsf(entry: AuditLog) -> dict[str, Any]:
    event = AuditEvent(entry.event)
    class_uid, class_name, category_uid, category_name = _EVENT_CLASS.get(event, _AUTHORIZE)
    record: dict[str, Any] = {
        "time": int(entry.timestamp.replace(tzinfo=UTC).timestamp() * 1000),  # stored as naive UTC
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_name": event.value,
        "severity_id": _SEVERITY.get(event, 1),
        "status": "Failure" if event in _FAILURES else "Success",
        "message": entry.detail,
        "metadata": {"product": PRODUCT, "uid": entry.hash, "sequence": entry.id, "version": "1.1.0"},
        "unmapped": {"aegis_event": event.value, "request_id": entry.request_id, "prev_hash": entry.prev_hash},
    }
    if entry.actor_id is not None:
        record["actor"] = {"user": {"uid": str(entry.actor_id)}}
    if entry.user_id is not None:
        record["user"] = {"uid": str(entry.user_id)}
    if entry.resource:
        record["resources"] = [{"name": entry.resource, "type": "aegis_resource"}]
    if entry.action:
        record["unmapped"]["action"] = entry.action
    return record


_handler: logging.Handler | None = None


def configure() -> None:
    global _handler
    target = os.getenv("AEGIS_SIEM_LOG_FILE")
    if not target or _handler is not None:
        return
    _handler = logging.StreamHandler(sys.stdout) if target == "stdout" else logging.FileHandler(target)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)


def reset() -> None:
    global _handler
    if _handler is not None:
        logger.removeHandler(_handler)
        _handler.close()
        _handler = None


def emit(entries: list[AuditLog]) -> None:
    if _handler is None:
        return
    for entry in entries:
        logger.info(json.dumps(to_ocsf(entry), separators=(",", ":"), default=str))
