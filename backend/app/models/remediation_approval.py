from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base
from backend.app.models.types import UTCDateTime


class RemediationApproval(Base):
    __tablename__ = "remediation_approvals"
    __table_args__ = (
        CheckConstraint("decision IN ('PENDING','APPROVED','REJECTED','EXPIRED')", name="ck_remediation_approval_decision"),
        CheckConstraint("requested_action IN ('restart_deployment','scale_deployment')", name="ck_remediation_approval_action"),
        Index("ix_remediation_approvals_decision_expiration", "decision", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False, index=True)
    requested_action: Mapped[str] = mapped_column(String(40), nullable=False)
    action_parameters: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    policy_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=lambda: datetime.now(timezone.utc))
    decision: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    decided_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    requester_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    remediation_action_id: Mapped[str | None] = mapped_column(ForeignKey("healing_actions.id", ondelete="SET NULL"), nullable=True, unique=True)
