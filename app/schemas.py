"""Pydantic request/response models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models import (
    AlertSeverity,
    AlertStatus,
    AuditEvent,
    CampaignStatus,
    CertificationDecision,
    RequestStatus,
    SensitivityLevel,
)

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
    mfa_enrolled: bool = Field(False, validation_alias="totp_confirmed")


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


class MfaEnrollOut(BaseModel):
    """Shown once: the shared secret, and the otpauth:// URI an authenticator app scans."""

    secret: str
    otpauth_uri: str


class StepUpIn(BaseModel):
    code: str = Field(min_length=6, max_length=7, examples=["123456"])


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int


class ResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    sensitivity_level: SensitivityLevel
    owner_department: str | None
    aws_service: str | None
    aws_resource_arn: str | None
    aws_role_arn: str | None


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
    credentials_issued_at: datetime | None
    revoked_at: datetime | None
    revoked_by_id: int | None
    revoke_reason: str | None


class CredentialsOut(BaseModel):
    """Temporary AWS credentials for one grant. Returned once per call and never stored by Aegis."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    role_arn: str
    session_name: str
    session_policy: dict


class CommentIn(BaseModel):
    comment: str = Field(min_length=3, max_length=1000)


class RevokeIn(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class CertificationTaskOut(BaseModel):
    item_id: int
    campaign_id: int
    campaign: str
    due_at: datetime


class ApprovalTaskOut(BaseModel):
    kind: Literal["approval", "break_glass_review", "certification"]
    eligibility: str
    request: RequestOut
    certification: CertificationTaskOut | None = None


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


# --- Governance --------------------------------------------------------------


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    rule: str
    severity: AlertSeverity
    status: AlertStatus
    user_id: int
    request_id: int | None
    detail: str
    resolved_by_id: int | None
    resolved_at: datetime | None
    resolution_note: str | None


class AlertResolveIn(BaseModel):
    note: str = Field(min_length=3, max_length=1000)
    false_positive: bool = False


class UserAccessReview(BaseModel):
    user_id: int
    email: str
    department: str
    role: str
    manager_id: int | None
    is_active: bool
    active_grants: list[str]
    resources_accessed: list[str]
    grants_in_period: int
    denied_in_period: int
    break_glass_in_period: int
    break_glass_unreviewed: int
    approvals_given: int
    open_alerts: int
    recommendation: str


class ControlChecks(BaseModel):
    """Evidence that the preventive controls held during the period (all should be 0 / true)."""

    self_approvals: int
    active_grants_for_inactive_users: int
    unreviewed_break_glass: int
    audit_chain_valid: bool


class AccessReviewReport(BaseModel):
    generated_at: datetime
    period_days: int
    control_checks: ControlChecks
    users: list[UserAccessReview]


# --- Policy simulation ---------------------------------------------------------------


class SimulateIn(BaseModel):
    """A what-if question for the policy engine. Nothing is granted or recorded as a request.

    Leave the overrides empty to ask about the person and resource as they are; set them to ask
    "what if": what if Alice moved to Finance, what if prod-db were reclassified as restricted.
    """

    user_id: int
    resource: str = Field(min_length=1, max_length=120)
    action: Action
    duration_hours: int = Field(1, ge=1, le=720)
    justification: str = Field("What-if simulation", max_length=500)
    mfa: bool = True
    approved: bool = False
    break_glass: bool = False
    role: str | None = Field(None, min_length=1, max_length=80)
    department: str | None = Field(None, min_length=1, max_length=80)
    sensitivity: SensitivityLevel | None = None


class SimulateOut(BaseModel):
    outcome: Literal["allow", "needs-approval", "step-up", "deny"]
    decision: Decision
    reasons: list[str]
    policy_ids: list[str]
    granted_duration_hours: int
    role: str
    department: str
    sensitivity: SensitivityLevel
    owner_department: str | None


class PolicyTestOut(BaseModel):
    name: str
    passed: bool
    expected: str
    actual: str
    because: list[str] | None
    policies: list[str]


class PolicyTestsOut(BaseModel):
    passed: int
    failed: int
    cases: list[PolicyTestOut]


# --- Access recertification -------------------------------------------------------------


class CampaignIn(BaseModel):
    name: str = Field(min_length=3, max_length=120, examples=["Q3 access recertification"])
    due_in_hours: int = Field(24, ge=1, le=720)


class CertificationItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    decision: CertificationDecision
    decided_by_id: int | None
    decided_at: datetime | None
    comment: str | None
    request: RequestOut


class CampaignOut(BaseModel):
    id: int
    name: str
    status: CampaignStatus
    created_by_id: int
    created_at: datetime
    due_at: datetime
    closed_at: datetime | None
    counts: dict[str, int]


class CampaignDetailOut(CampaignOut):
    items: list[CertificationItemOut]
