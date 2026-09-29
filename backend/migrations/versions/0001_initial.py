"""Create the Phase 1 relational schema."""
from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(80), nullable=False, unique=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(160), nullable=False),
        sa.Column("incident_type", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("classification", sa.String(160)),
        sa.Column("confidence", sa.Float()),
        sa.Column("recommended_action", sa.Text()),
        sa.Column("record_hash", sa.String(64)),
        sa.Column("signature_algorithm", sa.String(48)),
        sa.Column("signature", sa.Text()),
        sa.Column("signature_verified", sa.Boolean()),
        sa.Column("kem_algorithm", sa.String(48)),
        sa.Column("encryption_status", sa.String(32), nullable=False),
        sa.Column("blockchain_tx_id", sa.String(128)),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for field in ("source", "incident_type", "severity", "status", "record_hash", "created_at"):
        op.create_index(f"ix_incidents_{field}", "incidents", [field])

    op.create_table(
        "healing_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(160), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(24), nullable=False),
        sa.Column("verification_status", sa.String(32), nullable=False),
        sa.Column("details", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_healing_actions_incident_id", "healing_actions", ["incident_id"])
    op.create_index("ix_healing_actions_status", "healing_actions", ["status"])
    op.create_index("ix_healing_actions_created_at", "healing_actions", ["created_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="SET NULL")),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("event_data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for field in ("actor_id", "incident_id", "event_type", "created_at"):
        op.create_index(f"ix_audit_events_{field}", "audit_events", [field])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("healing_actions")
    op.drop_table("incidents")
    op.drop_table("users")
