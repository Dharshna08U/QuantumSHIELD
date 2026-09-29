"""Persist incident analysis, PQC, blockchain, and audit transition status."""
from alembic import op
import sqlalchemy as sa


revision = "0002_incident_pipeline"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _column(table: str, name: str, type_, **kwargs) -> None:
    op.add_column(table, sa.Column(name, type_, **kwargs))


def upgrade() -> None:
    incident_fields = [
        ("summary", sa.String(240), False, ""),
        ("description", sa.Text(), True, None),
        ("encryption_required", sa.Boolean(), False, "0"),
        ("ai_status", sa.String(24), False, "pending"),
        ("analysis_details", sa.JSON(), False, "{}"),
        ("auto_healing_eligible", sa.Boolean(), True, None),
        ("healing_status", sa.String(32), False, "not_requested"),
        ("pqc_status", sa.String(24), False, "not_performed"),
        ("encryption_metadata", sa.JSON(), False, "{}"),
        ("encrypted_payload", sa.Text(), True, None),
        ("blockchain_provider", sa.String(24), False, "disabled"),
        ("blockchain_status", sa.String(24), False, "not_performed"),
        ("blockchain_timestamp", sa.DateTime(timezone=True), True, None),
        ("blockchain_verified", sa.Boolean(), True, None),
        ("updated_at", sa.DateTime(timezone=True), False, sa.text("CURRENT_TIMESTAMP")),
    ]
    for name, column_type, nullable, default in incident_fields:
        kwargs = {"nullable": nullable}
        if default is not None:
            kwargs["server_default"] = sa.text(f"'{default}'") if isinstance(default, str) else default
        _column("incidents", name, column_type, **kwargs)
    with op.batch_alter_table("incidents") as batch:
        batch.create_check_constraint(
            "ck_incident_confidence", "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)"
        )
    for field in ("ai_status", "healing_status", "pqc_status", "blockchain_status"):
        op.create_index(f"ix_incidents_{field}", "incidents", [field])

    _column("audit_events", "actor_type", sa.String(24), nullable=False, server_default="system")
    _column("audit_events", "result", sa.String(32), nullable=False, server_default="success")


def downgrade() -> None:
    op.drop_column("audit_events", "result")
    op.drop_column("audit_events", "actor_type")
    for field in ("ai_status", "healing_status", "pqc_status", "blockchain_status"):
        op.drop_index(f"ix_incidents_{field}", table_name="incidents")
    with op.batch_alter_table("incidents") as batch:
        batch.drop_constraint("ck_incident_confidence", type_="check")
    for name in (
        "updated_at", "blockchain_verified", "blockchain_timestamp", "blockchain_status",
        "blockchain_provider", "encrypted_payload", "encryption_metadata", "pqc_status",
        "healing_status", "auto_healing_eligible", "analysis_details", "ai_status",
        "encryption_required", "description", "summary",
    ):
        op.drop_column("incidents", name)
