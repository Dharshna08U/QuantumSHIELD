from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base
from backend.app.models.types import UTCDateTime


class HealingAction(Base):
    __tablename__ = "healing_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"), index=True)
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(32), default="proposed", index=True)
    mode: Mapped[str] = mapped_column(String(24), default="simulation")
    verification_status: Mapped[str] = mapped_column(String(32), default="pending")
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=lambda: datetime.now(timezone.utc), index=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    incident: Mapped["Incident"] = relationship(back_populates="healing_actions")
