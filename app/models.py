"""ORM models: users, resources, access requests and the audit trail."""

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
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
    ACTIVE = "ACTIVE"  # granted and not yet expired
    DENIED = "DENIED"  # rejected by the policy evaluator
    REVOKED = "REVOKED"  # grant expired and was revoked by the scheduler


class AuditEvent(str, enum.Enum):
    REQUEST_SUBMITTED = "REQUEST_SUBMITTED"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    ACCESS_REVOKED = "ACCESS_REVOKED"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    department: Mapped[str] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(80))

    requests: Mapped[list["AccessRequest"]] = relationship(back_populates="user")


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    sensitivity_level: Mapped[SensitivityLevel] = mapped_column(
        Enum(SensitivityLevel, native_enum=False, length=20)
    )
    # Department that owns the resource. Confidential and restricted resources are only
    # granted to members of this department (or to cross-department roles, see evaluator).
    owner_department: Mapped[str | None] = mapped_column(String(80), nullable=True)


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    resource: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(20))
    status: Mapped[RequestStatus] = mapped_column(
        Enum(RequestStatus, native_enum=False, length=20), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    request_text: Mapped[str] = mapped_column(Text)
    allow_reason: Mapped[str] = mapped_column(Text, default="")
    duration_hours: Mapped[int] = mapped_column(Integer, default=0)
    decision_reason: Mapped[str] = mapped_column(Text, default="")
    parser: Mapped[str] = mapped_column(String(40), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="requests")


class AuditLog(Base):
    """Append-only history of every request, decision and revocation."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event: Mapped[AuditEvent] = mapped_column(Enum(AuditEvent, native_enum=False, length=30))
    request_id: Mapped[int | None] = mapped_column(ForeignKey("access_requests.id"), nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resource: Mapped[str | None] = mapped_column(String(120), nullable=True)
    action: Mapped[str | None] = mapped_column(String(20), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
