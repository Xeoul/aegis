"""ORM models: users, resources, access requests and the audit trail."""

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, utcnow


class SensitivityLevel(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return list(SensitivityLevel).index(self) + 1


class RequestStatus(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"  # policy allows it, waiting for a human approver
    ACTIVE = "ACTIVE"  # granted and not yet expired
    DENIED = "DENIED"  # rejected by the policy evaluator
    REJECTED = "REJECTED"  # rejected by an approver
    EXPIRED = "EXPIRED"  # nobody approved it before the approval deadline
    REVOKED = "REVOKED"  # grant ended: expired, revoked early, or owner deprovisioned


class AuditEvent(str, enum.Enum):
    REQUEST_SUBMITTED = "REQUEST_SUBMITTED"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    ACCESS_REVOKED = "ACCESS_REVOKED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    REQUEST_APPROVED = "REQUEST_APPROVED"
    REQUEST_REJECTED = "REQUEST_REJECTED"
    REQUEST_EXPIRED = "REQUEST_EXPIRED"
    BREAK_GLASS_USED = "BREAK_GLASS_USED"
    BREAK_GLASS_REVIEWED = "BREAK_GLASS_REVIEWED"
    CREDENTIALS_ISSUED = "CREDENTIALS_ISSUED"
    CLOUD_SESSIONS_REVOKED = "CLOUD_SESSIONS_REVOKED"
    CLOUD_REVOCATION_FAILED = "CLOUD_REVOCATION_FAILED"
    ALERT_RAISED = "ALERT_RAISED"
    ALERT_RESOLVED = "ALERT_RESOLVED"
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_DEACTIVATED = "USER_DEACTIVATED"


class AlertSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    # Stable identifier shared with the identity provider; tokens are matched on it.
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    department: Mapped[str] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(80))
    # Platform administrators manage identities. They get no extra resource access.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    manager_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    requests: Mapped[list["AccessRequest"]] = relationship(back_populates="user", foreign_keys="AccessRequest.user_id")
    manager: Mapped["User | None"] = relationship(remote_side=[id], foreign_keys=[manager_id])


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    sensitivity_level: Mapped[SensitivityLevel] = mapped_column(Enum(SensitivityLevel, native_enum=False, length=20))
    # Department that owns the resource. Confidential and restricted resources are only
    # granted to members of this department (or to cross-department roles, see evaluator).
    owner_department: Mapped[str | None] = mapped_column(String(80), nullable=True)

    # Optional AWS backing: grants on this resource can be exchanged for STS credentials.
    aws_service: Mapped[str | None] = mapped_column(String(40), nullable=True)  # s3, dynamodb, ...
    aws_resource_arn: Mapped[str | None] = mapped_column(String(300), nullable=True)
    aws_role_arn: Mapped[str | None] = mapped_column(String(300), nullable=True)


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    resource: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(20))
    status: Mapped[RequestStatus] = mapped_column(Enum(RequestStatus, native_enum=False, length=20), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    request_text: Mapped[str] = mapped_column(Text)
    allow_reason: Mapped[str] = mapped_column(Text, default="")
    duration_hours: Mapped[int] = mapped_column(Integer, default=0)
    decision_reason: Mapped[str] = mapped_column(Text, default="")
    parser: Mapped[str] = mapped_column(String(40), default="")
    # Comma-separated prompt-manipulation patterns found in request_text (see llm_parser).
    risk_flags: Mapped[str] = mapped_column(String(200), default="")

    # Approval workflow
    approval_deadline: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decision_comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Emergency access that skipped approval and must be reviewed afterwards
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Set once AWS credentials have been issued, so early revocation knows to deny sessions.
    credentials_issued_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped[User] = relationship(back_populates="requests", foreign_keys=[user_id])


class AuditLog(Base):
    """Append-only, hash-chained history of every request, decision and revocation.

    Rows are written only through ``app.audit``; see that module for the chaining scheme.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event: Mapped[AuditEvent] = mapped_column(Enum(AuditEvent, native_enum=False, length=30))
    request_id: Mapped[int | None] = mapped_column(ForeignKey("access_requests.id"), nullable=True)
    # user_id is the subject of the event; actor_id is who caused it (None = the system).
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resource: Mapped[str | None] = mapped_column(String(120), nullable=True)
    action: Mapped[str | None] = mapped_column(String(20), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class Alert(Base):
    """A detection-rule finding for the security team to triage."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    rule: Mapped[str] = mapped_column(String(60), index=True)
    severity: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity, native_enum=False, length=10))
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, native_enum=False, length=20), default=AlertStatus.OPEN, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    request_id: Mapped[int | None] = mapped_column(ForeignKey("access_requests.id"), nullable=True)
    detail: Mapped[str] = mapped_column(Text)
    resolved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
