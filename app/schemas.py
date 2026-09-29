"""Pydantic request/response models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models import AuditEvent, RequestStatus, SensitivityLevel

Action = Literal["read", "write", "delete", "admin"]
Decision = Literal["ALLOW", "DENY"]


# --- Users & resources -------------------------------------------------------


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    department: str = Field(min_length=1, max_length=80, examples=["Engineering"])
    role: str = Field(min_length=1, max_length=80, examples=["engineer"])
    is_admin: bool = False
    manager_id: int | None = None

    @field_validator("email")
    @classmethod
    def _lower_email(cls, v: str) -> str:
        return v.lower()


class UserOut(UserCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool


class UserUpdate(BaseModel):
    """Joiner/mover/leaver changes. Any change to access-relevant attributes revokes open grants."""

    department: str | None = Field(None, min_length=1, max_length=80)
    role: str | None = Field(None, min_length=1, max_length=80)
    manager_id: int | None = None
    is_admin: bool | None = None
    is_active: bool | None = None


# --- Authentication ------------------------------------------------------------


class DevTokenRequest(BaseModel):
    email: EmailStr


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    sensitivity_level: SensitivityLevel
    owner_department: str | None


# --- Natural-language request & parsed policy -------------------------------


class AccessRequestIn(BaseModel):
    """An access request written in plain English. The requester is the authenticated caller."""

    request_text: str = Field(
        min_length=5,
        max_length=2000,
        examples=["I need read access to the prod-db for 4 hours to debug a failing migration"],
    )
    break_glass: bool = Field(
        False,
        description="Emergency access: skip approval for a request that needs it. Capped at 1h and "
        "flagged for mandatory post-incident review. The policy rules still apply.",
    )


class ParsedPolicy(BaseModel):
    """What the LLM extracts from the request text. Kept flat so it maps cleanly to a JSON schema."""

    resource: str = Field(description="Exact name of the requested resource from the catalog, or 'unknown'.")
    action: Action = Field(description="The single action requested.")
    allow_reason: str = Field(description="One-sentence business justification stated by the requester.")
    duration_hours: int = Field(description="Requested access duration in whole hours.")


class PolicySubject(BaseModel):
    user_id: int
    role: str
    department: str


class PolicyResource(BaseModel):
    name: str
    sensitivity_level: SensitivityLevel | None


class PolicyConditions(BaseModel):
    duration_hours: int
    not_after: datetime | None


class ABACPolicy(BaseModel):
    """Fully resolved attribute-based policy statement for a single grant."""

    effect: Decision
    subject: PolicySubject
    resource: PolicyResource
    action: Action
    conditions: PolicyConditions
    justification: str


class AccessDecisionOut(BaseModel):
    request_id: int
    decision: Decision
    status: RequestStatus
    requires_approval: bool
    break_glass: bool
    approval_deadline: datetime | None
    risk_flags: list[str]
    reasons: list[str]
    parsed: ParsedPolicy
    parser: str
    policy: ABACPolicy


# --- Grants & audit ---------------------------------------------------------


class GrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    resource: str
    action: str
    status: RequestStatus
    created_at: datetime
    expires_at: datetime | None
    duration_hours: int
    allow_reason: str
    break_glass: bool


class RequestOut(GrantOut):
    """Full lifecycle view of one access request."""

    request_text: str
    decision_reason: str
    parser: str
    risk_flags: str
    approval_deadline: datetime | None
    decided_by_id: int | None
    decided_at: datetime | None
    decision_comment: str | None
    reviewed_by_id: int | None
    reviewed_at: datetime | None
    revoked_at: datetime | None
    revoked_by_id: int | None
    revoke_reason: str | None


class CommentIn(BaseModel):
    comment: str = Field(min_length=3, max_length=1000)


class RevokeIn(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class ApprovalTaskOut(BaseModel):
    kind: Literal["approval", "break_glass_review"]
    eligibility: str
    request: RequestOut


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event: AuditEvent
    request_id: int | None
    user_id: int | None
    actor_id: int | None
    resource: str | None
    action: str | None
    detail: str
    prev_hash: str
    hash: str


class AuditVerificationOut(BaseModel):
    valid: bool
    entries_checked: int
    head_hash: str
    first_invalid_id: int | None
    reason: str | None
