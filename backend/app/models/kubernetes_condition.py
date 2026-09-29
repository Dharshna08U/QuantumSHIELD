from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base
from backend.app.models.types import UTCDateTime


class KubernetesCondition(Base):
    __tablename__ = "kubernetes_conditions"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_kubernetes_conditions_fingerprint"),
        CheckConstraint("status IN ('ACTIVE','RESOLVED','SUPPRESSED')", name="ck_kubernetes_condition_status"),
        CheckConstraint("occurrence_count >= 1", name="ck_kubernetes_condition_occurrence_count"),
        Index("ix_kubernetes_conditions_status_last_seen", "status", "last_seen"),
        Index("ix_kubernetes_conditions_cluster_status", "cluster_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    cluster_id: Mapped[str] = mapped_column(String(64), nullable=False)
    condition_type: Mapped[str] = mapped_column(String(80), nullable=False)
    namespace: Mapped[str] = mapped_column(String(63), nullable=False)
    resource: Mapped[str] = mapped_column(String(253), nullable=False)
    summary: Mapped[str] = mapped_column(String(240), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE", index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=lambda: datetime.now(timezone.utc))
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    observation: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
