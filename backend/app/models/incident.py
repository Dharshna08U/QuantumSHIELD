from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, Float, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base
from backend.app.models.types import UTCDateTime


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_incident_confidence"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source: Mapped[str] = mapped_column(String(160), index=True)
    incident_type: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(24), index=True)
    status: Mapped[str] = mapped_column(String(32), default="detected", index=True)
    summary: Mapped[str] = mapped_column(String(240), default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    encryption_required: Mapped[bool] = mapped_column(Boolean, default=False)
    classification: Mapped[str | None] = mapped_column(String(160), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    analysis_details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    auto_healing_eligible: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    healing_status: Mapped[str] = mapped_column(String(32), default="not_requested", index=True)
    record_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    pqc_status: Mapped[str] = mapped_column(String(24), default="not_performed", index=True)
    signature_algorithm: Mapped[str | None] = mapped_column(String(48), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signature_verified: Mapped[bool | None] = mapped_column(nullable=True)
    kem_algorithm: Mapped[str | None] = mapped_column(String(48), nullable=True)
    encryption_status: Mapped[str] = mapped_column(String(32), default="not_performed")
    encryption_metadata: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    encrypted_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    blockchain_provider: Mapped[str] = mapped_column(String(24), default="disabled")
    blockchain_status: Mapped[str] = mapped_column(String(24), default="not_performed", index=True)
    blockchain_timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    blockchain_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    blockchain_tx_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attributes: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(back_populates="incident", order_by="AuditEvent.created_at")
    healing_actions: Mapped[list["HealingAction"]] = relationship(back_populates="incident")
