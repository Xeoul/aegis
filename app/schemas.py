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

    @field_validator("email")
    @classmethod
    def _lower_email(cls, v: str) -> str:
        return v.lower()


class UserOut(UserCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool


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
