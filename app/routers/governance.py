"""Security operations and compliance: alert triage and periodic access reviews."""

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, siem
from app.auth import get_current_user, require_oversight
from app.database import get_db, utcnow
from app.models import AccessRequest, Alert, AlertSeverity, AlertStatus, AuditEvent, AuditLog, RequestStatus, User
from app.schemas import AccessReviewReport, AlertOut, AlertResolveIn, ControlChecks, UserAccessReview

router = APIRouter()

TRIAGE_ROLES = {"security engineer"}


@router.get("/alerts", response_model=list[AlertOut], tags=["governance"])
def list_alerts(
    status_: AlertStatus | None = Query(AlertStatus.OPEN, alias="status"),
    severity: AlertSeverity | None = Query(None),
    _: User = Depends(require_oversight),
    db: Session = Depends(get_db),
) -> list[Alert]:
    query = select(Alert).order_by(Alert.id.desc())
    if status_ is not None:
        query = query.where(Alert.status == status_)
    if severity is not None:
        query = query.where(Alert.severity == severity)
    return list(db.scalars(query))


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut, tags=["governance"])
def resolve_alert(
    alert_id: int, payload: AlertResolveIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Alert:
    """Close an alert. Security engineers only, and never an alert about themselves."""
    if user.role.strip().lower() not in TRIAGE_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only security engineers triage alerts")
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Alert {alert_id} not found")
    if alert.user_id == user.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Separation of duties: you cannot resolve an alert about yourself"
        )
    if alert.status != AlertStatus.OPEN:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Alert is already {alert.status.value}")
    alert.status = AlertStatus.FALSE_POSITIVE if payload.false_positive else AlertStatus.RESOLVED
    alert.resolved_by_id, alert.resolved_at, alert.resolution_note = user.id, utcnow(), payload.note
    audit.record(
        db,
        AuditEvent.ALERT_RESOLVED,
        request_id=alert.request_id,
        user_id=alert.user_id,
        actor_id=user.id,
        detail=f"alert={alert.id} rule={alert.rule} -> {alert.status.value}: {payload.note}",
    )
    audit.commit(db)
    return alert


def build_access_review(db: Session, days: int) -> AccessReviewReport:
    now = utcnow()
    since = now - timedelta(days=days)
    users = list(db.scalars(select(User).order_by(User.id)))
    period = list(db.scalars(select(AccessRequest).where(AccessRequest.created_at >= since)))
    active = list(
        db.scalars(
            select(AccessRequest).where(AccessRequest.status == RequestStatus.ACTIVE, AccessRequest.expires_at > now)
        )
    )
    open_alerts = Counter(db.scalars(select(Alert.user_id).where(Alert.status == AlertStatus.OPEN)))
    unreviewed = Counter(
        r.user_id
        for r in db.scalars(
            select(AccessRequest).where(AccessRequest.break_glass.is_(True), AccessRequest.reviewed_at.is_(None))
        )
    )
    approvals = Counter(r.decided_by_id for r in period if r.decided_by_id and r.status != RequestStatus.REJECTED)

    by_user: dict[int, list[AccessRequest]] = defaultdict(list)
    for r in period:
        by_user[r.user_id].append(r)
    active_by_user: dict[int, list[str]] = defaultdict(list)
    for r in active:
        active_by_user[r.user_id].append(f"{r.resource}:{r.action}")

    rows = []
    for u in users:
        reqs = by_user.get(u.id, [])
        granted = [r for r in reqs if r.status in (RequestStatus.ACTIVE, RequestStatus.REVOKED)]
        if not u.is_active and active_by_user.get(u.id):
            rec = "REVOKE: deactivated user still holds access"
        elif unreviewed.get(u.id):
            rec = "INVESTIGATE: unreviewed break-glass use"
        elif open_alerts.get(u.id):
            rec = "INVESTIGATE: open security alerts"
        elif active_by_user.get(u.id):
            rec = "CERTIFY: confirm the active grants are still needed"
        else:
            rec = "NO ACTION: no standing or active access"
        rows.append(
            UserAccessReview(
                user_id=u.id,
                email=u.email,
                department=u.department,
                role=u.role,
                manager_id=u.manager_id,
                is_active=u.is_active,
                active_grants=sorted(active_by_user.get(u.id, [])),
                resources_accessed=sorted({r.resource for r in granted}),
                grants_in_period=len(granted),
                denied_in_period=sum(r.status == RequestStatus.DENIED for r in reqs),
                break_glass_in_period=sum(r.break_glass for r in reqs),
                break_glass_unreviewed=unreviewed.get(u.id, 0),
                approvals_given=approvals.get(u.id, 0),
                open_alerts=open_alerts.get(u.id, 0),
                recommendation=rec,
            )
        )

    inactive_ids = {u.id for u in users if not u.is_active}
    return AccessReviewReport(
        generated_at=now,
        period_days=days,
        control_checks=ControlChecks(
            self_approvals=sum(1 for r in period if r.decided_by_id is not None and r.decided_by_id == r.user_id),
            active_grants_for_inactive_users=sum(1 for r in active if r.user_id in inactive_ids),
            unreviewed_break_glass=sum(unreviewed.values()),
            audit_chain_valid=audit.verify_chain(db).valid,
        ),
        users=rows,
    )


@router.get("/reports/access-review", response_model=AccessReviewReport, tags=["governance"])
def access_review(
    days: int = Query(30, ge=1, le=365),
    format: str = Query("json", pattern="^(json|csv)$"),
    _: User = Depends(require_oversight),
    db: Session = Depends(get_db),
):
    """Periodic user access review (certification) with control-effectiveness evidence."""
    report = build_access_review(db, days)
    if format == "json":
        return report
    buf = io.StringIO()
    fields = list(UserAccessReview.model_fields)
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for row in report.users:
        data = row.model_dump()
        data["active_grants"] = ";".join(data["active_grants"])
        data["resources_accessed"] = ";".join(data["resources_accessed"])
        writer.writerow(data)
    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="access-review-{report.generated_at:%Y%m%d}.csv"'},
    )


@router.get("/audit-logs/export", tags=["audit"])
def export_audit_logs(
    after_id: int = Query(0, ge=0, description="Cursor: return entries with id greater than this"),
    limit: int = Query(1000, ge=1, le=10000),
    _: User = Depends(require_oversight),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """OCSF-style NDJSON for SIEM pull ingestion. Use the last ``metadata.sequence`` as the next cursor."""
    entries = list(db.scalars(select(AuditLog).where(AuditLog.id > after_id).order_by(AuditLog.id).limit(limit)))
    lines = (json.dumps(siem.to_ocsf(e), separators=(",", ":"), default=str) + "\n" for e in entries)
    return StreamingResponse(lines, media_type="application/x-ndjson")
