from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, certification, workflow
from app.auth import get_current_user, require_oversight
from app.database import get_db
from app.models import (
    CampaignStatus,
    CertificationCampaign,
    CertificationDecision,
    CertificationItem,
    RequestStatus,
    Resource,
    User,
)
from app.schemas import CampaignDetailOut, CampaignIn, CampaignOut, CertificationItemOut, CommentIn

router = APIRouter(tags=["certification"])


def _out(campaign: CertificationCampaign) -> dict:
    return {
        "id": campaign.id,
        "name": campaign.name,
        "status": campaign.status,
        "created_by_id": campaign.created_by_id,
        "created_at": campaign.created_at,
        "due_at": campaign.due_at,
        "closed_at": campaign.closed_at,
        "counts": certification.counts(campaign),
    }


@router.post("/certifications", response_model=CampaignDetailOut, status_code=status.HTTP_201_CREATED)
def start_campaign(
    payload: CampaignIn, user: User = Depends(require_oversight), db: Session = Depends(get_db)
) -> CampaignDetailOut:
    """Start a recertification of every active grant (auditors, security engineers, admins)."""
    campaign = certification.start(db, payload.name, payload.due_in_hours, user)
    audit.commit(db)
    db.refresh(campaign)
    items = [CertificationItemOut.model_validate(i) for i in campaign.items]
    return CampaignDetailOut(**_out(campaign), items=items)


@router.get("/certifications", response_model=list[CampaignOut], dependencies=[Depends(require_oversight)])
def list_campaigns(db: Session = Depends(get_db)) -> list[CampaignOut]:
    campaigns = db.scalars(select(CertificationCampaign).order_by(CertificationCampaign.id.desc())).all()
    return [CampaignOut(**_out(c)) for c in campaigns]


@router.get(
    "/certifications/{campaign_id}", response_model=CampaignDetailOut, dependencies=[Depends(require_oversight)]
)
def get_campaign(campaign_id: int, db: Session = Depends(get_db)) -> CampaignDetailOut:
    campaign = db.get(CertificationCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Campaign {campaign_id} not found")
    return CampaignDetailOut(**_out(campaign), items=[CertificationItemOut.model_validate(i) for i in campaign.items])


def _decide(item_id: int, payload: CommentIn, user: User, db: Session, certify: bool) -> CertificationItemOut:
    item = db.get(CertificationItem, item_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Certification item {item_id} not found")
    resource = db.scalar(select(Resource).where(Resource.name == item.request.resource))
    ok, reason = workflow.approver_eligibility(user, item.request, resource)
    if not ok:
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)
    if item.campaign.status != CampaignStatus.OPEN or item.decision != CertificationDecision.PENDING:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {item.decision.value.lower()}")
    if item.request.status != RequestStatus.ACTIVE:
        certification.mark_ended(item)
        db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "This grant has already ended")
    certification.decide(db, item, user, certify, payload.comment)
    audit.commit(db)
    return CertificationItemOut.model_validate(item)


@router.post("/certifications/items/{item_id}/certify", response_model=CertificationItemOut)
def certify(
    item_id: int, payload: CommentIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> CertificationItemOut:
    """Confirm the access is still needed. Same reviewers as approval, never the grantee."""
    return _decide(item_id, payload, user, db, certify=True)


@router.post("/certifications/items/{item_id}/revoke", response_model=CertificationItemOut)
def revoke(
    item_id: int, payload: CommentIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> CertificationItemOut:
    return _decide(item_id, payload, user, db, certify=False)
