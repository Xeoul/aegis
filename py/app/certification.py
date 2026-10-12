"""Access recertification: reviewers re-confirm every active grant, or it's revoked.

Just-in-time grants are short, but the longer ones (up to 72 hours on public resources, 24 on
internal) and anything granted under attributes that have since drifted are worth a second
look. A campaign snapshots every active grant; the people who could approve that access
(the grantee's manager, a manager of the owning department, or security, never the grantee)
certify or revoke each one. Whatever is still unreviewed at the deadline is revoked: an
access review that can be ignored isn't a control.
"""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, workflow
from app.database import utcnow
from app.models import (
    AccessRequest,
    AuditEvent,
    CampaignStatus,
    CertificationCampaign,
    CertificationDecision,
    CertificationItem,
    RequestStatus,
    User,
)


def start(db: Session, name: str, due_in_hours: int, actor: User) -> CertificationCampaign:
    now = utcnow()
    campaign = CertificationCampaign(
        name=name, created_by_id=actor.id, created_at=now, due_at=now + timedelta(hours=due_in_hours)
    )
    db.add(campaign)
    grants = db.scalars(
        select(AccessRequest).where(AccessRequest.status == RequestStatus.ACTIVE).order_by(AccessRequest.id)
    ).all()
    for grant in grants:
        db.add(CertificationItem(campaign=campaign, request_id=grant.id))
    db.flush()
    audit.record(
        db,
        AuditEvent.CERTIFICATION_STARTED,
        actor_id=actor.id,
        detail=f"Campaign {campaign.id} '{name}': {len(grants)} grants to review by {campaign.due_at.isoformat()}Z.",
    )
    return campaign


def decide(db: Session, item: CertificationItem, reviewer: User, certify: bool, comment: str) -> None:
    """Record a reviewer's decision. The caller has checked eligibility and that it's pending."""
    item.decided_by_id, item.decided_at, item.comment = reviewer.id, utcnow(), comment
    if certify:
        item.decision = CertificationDecision.CERTIFIED
        audit.record_request(
            db,
            AuditEvent.ACCESS_CERTIFIED,
            item.request,
            actor_id=reviewer.id,
            detail=f"Certified in campaign {item.campaign_id}: {comment}",
        )
    else:
        item.decision = CertificationDecision.REVOKED
        workflow.revoke(db, item.request, reviewer.id, f"Recertification (campaign {item.campaign_id}): {comment}")


def mark_ended(item: CertificationItem) -> None:
    item.decision, item.decided_at = CertificationDecision.ENDED, utcnow()


def close_overdue() -> int:
    """Scheduler job: close campaigns past their deadline, revoking whatever wasn't certified."""
    from app.database import SessionLocal

    revoked = 0
    with SessionLocal() as db:
        campaigns = db.scalars(
            select(CertificationCampaign).where(
                CertificationCampaign.status == CampaignStatus.OPEN, CertificationCampaign.due_at <= utcnow()
            )
        ).all()
        for campaign in campaigns:
            for item in campaign.items:
                if item.decision != CertificationDecision.PENDING:
                    continue
                if item.request.status != RequestStatus.ACTIVE:
                    mark_ended(item)
                    continue
                item.decision, item.decided_at = CertificationDecision.REVOKED, utcnow()
                item.comment = "Not certified before the deadline."
                workflow.revoke(
                    db,
                    item.request,
                    None,
                    f"Recertification (campaign {campaign.id}): not certified before the deadline.",
                )
                revoked += 1
            campaign.status, campaign.closed_at = CampaignStatus.CLOSED, utcnow()
            audit.record(
                db,
                AuditEvent.CERTIFICATION_CLOSED,
                detail=f"Campaign {campaign.id} '{campaign.name}' closed; {counts(campaign)}.",
            )
        audit.commit(db)
    return revoked


def counts(campaign: CertificationCampaign) -> dict[str, int]:
    tally = {d.value.lower(): 0 for d in CertificationDecision}
    for item in campaign.items:
        tally[item.decision.value.lower()] += 1
    tally["total"] = len(campaign.items)
    return tally
