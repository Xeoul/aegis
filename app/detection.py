"""Detection rules that turn access activity into security alerts.

Rules run after every access request, inside the same transaction, so an alert and the
activity that caused it are committed (and audited) together. Each rule has a cooldown so
that one noisy user does not flood the queue.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.database import utcnow
from app.models import AccessRequest, Alert, AlertSeverity, AuditEvent, RequestStatus, Resource, SensitivityLevel

COOLDOWN = timedelta(hours=1)
DENIAL_WINDOW = timedelta(hours=1)
DENIAL_THRESHOLD = 3
BURST_WINDOW = timedelta(hours=24)
BURST_THRESHOLD = 5
ESCALATION_POLICIES = ("clearance", "privileged-actions")
SENSITIVE = (SensitivityLevel.CONFIDENTIAL, SensitivityLevel.RESTRICTED)


@dataclass
class Finding:
    rule: str
    severity: AlertSeverity
    detail: str


def _range(var: str, default: str) -> tuple[int, int]:
    start, end = os.getenv(var, default).split("-")
    return int(start), int(end)


def _business_hours() -> tuple[int, int]:
    return _range("AEGIS_BUSINESS_HOURS_UTC", "07-19")  # [start, end) hours


def _is_off_hours(ts: datetime) -> bool:
    start, end = _business_hours()
    first_day, last_day = _range("AEGIS_BUSINESS_DAYS", "0-4")  # Monday=0 .. Friday=4, inclusive
    return not (first_day <= ts.weekday() <= last_day) or not (start <= ts.hour < end)


def _prompt_injection(db: Session, req: AccessRequest, resource: Resource | None, now: datetime) -> Finding | None:
    if req.risk_flags:
        return Finding(
            "prompt-injection",
            AlertSeverity.HIGH,
            f"Request text matched manipulation patterns ({req.risk_flags}); held for human approval.",
        )
    return None


def _break_glass(db: Session, req: AccessRequest, resource: Resource | None, now: datetime) -> Finding | None:
    if req.break_glass:
        return Finding(
            "break-glass-used",
            AlertSeverity.HIGH,
            f"Emergency access to {req.resource} ({req.action}) without prior approval. Review required.",
        )
    return None


def _escalation_attempt(db: Session, req: AccessRequest, resource: Resource | None, now: datetime) -> Finding | None:
    if req.status == RequestStatus.DENIED and any(f"[{p}]" in req.decision_reason for p in ESCALATION_POLICIES):
        return Finding(
            "privilege-escalation-attempt",
            AlertSeverity.MEDIUM,
            f"Requested {req.action} on {req.resource} beyond the user's clearance or privileges.",
        )
    return None


def _repeated_denials(db: Session, req: AccessRequest, resource: Resource | None, now: datetime) -> Finding | None:
    if req.status != RequestStatus.DENIED:
        return None
    count = db.scalar(
        select(func.count())
        .select_from(AccessRequest)
        .where(
            AccessRequest.user_id == req.user_id,
            AccessRequest.status == RequestStatus.DENIED,
            AccessRequest.created_at >= now - DENIAL_WINDOW,
        )
    )
    if count and count >= DENIAL_THRESHOLD:
        return Finding(
            "repeated-denials",
            AlertSeverity.MEDIUM,
            f"{count} denied requests in the last {int(DENIAL_WINDOW.total_seconds() // 60)} minutes (possible probing).",
        )
    return None


def _off_hours_sensitive(db: Session, req: AccessRequest, resource: Resource | None, now: datetime) -> Finding | None:
    if resource is not None and resource.sensitivity_level in SENSITIVE and _is_off_hours(now):
        start, end = _business_hours()
        return Finding(
            "off-hours-sensitive-access",
            AlertSeverity.LOW,
            f"{resource.sensitivity_level.value} resource {resource.name} requested outside business hours "
            f"({start:02d}:00-{end:02d}:00 UTC, weekdays).",
        )
    return None


def _sensitive_burst(db: Session, req: AccessRequest, resource: Resource | None, now: datetime) -> Finding | None:
    sensitive_names = select(Resource.name).where(Resource.sensitivity_level.in_(SENSITIVE))
    count = db.scalar(
        select(func.count(func.distinct(AccessRequest.resource))).where(
            AccessRequest.user_id == req.user_id,
            AccessRequest.created_at >= now - BURST_WINDOW,
            AccessRequest.resource.in_(sensitive_names),
        )
    )
    if count and count >= BURST_THRESHOLD:
        return Finding(
            "sensitive-access-burst",
            AlertSeverity.MEDIUM,
            f"Requests for {count} different confidential/restricted resources in 24h (possible collection).",
        )
    return None


RULES: list[Callable[[Session, AccessRequest, Resource | None, datetime], Finding | None]] = [
    _prompt_injection,
    _break_glass,
    _escalation_attempt,
    _repeated_denials,
    _off_hours_sensitive,
    _sensitive_burst,
]


def scan(db: Session, req: AccessRequest, resource: Resource | None, now: datetime | None = None) -> list[Alert]:
    """Run every rule against a just-processed request and raise alerts. Caller commits."""
    now = now or utcnow()
    db.flush()  # make the current request visible to the aggregate queries
    raised = []
    for rule in RULES:
        finding = rule(db, req, resource, now)
        if finding is None:
            continue
        recent = db.scalar(
            select(Alert.id).where(
                Alert.user_id == req.user_id, Alert.rule == finding.rule, Alert.created_at >= now - COOLDOWN
            )
        )
        if recent is not None:
            continue
        alert = Alert(
            created_at=now,
            rule=finding.rule,
            severity=finding.severity,
            user_id=req.user_id,
            request_id=req.id,
            detail=finding.detail,
        )
        db.add(alert)
        db.flush()
        audit.record(
            db,
            AuditEvent.ALERT_RAISED,
            request_id=req.id,
            user_id=req.user_id,
            resource=req.resource,
            action=req.action,
            detail=f"alert={alert.id} rule={finding.rule} severity={finding.severity.value}: {finding.detail}",
        )
        raised.append(alert)
    return raised

