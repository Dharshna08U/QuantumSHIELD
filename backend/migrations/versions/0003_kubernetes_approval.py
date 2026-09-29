"""Persistent Kubernetes condition correlation and remediation approvals."""
from alembic import op
import sqlalchemy as sa


revision = "0003_kubernetes_approval"
down_revision = "0002_incident_pipeline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kubernetes_conditions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("cluster_id", sa.String(64), nullable=False),
        sa.Column("condition_type", sa.String(80), nullable=False),
        sa.Column("namespace", sa.String(63), nullable=False),
        sa.Column("resource", sa.String(253), nullable=False),
        sa.Column("summary", sa.String(240), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observation", sa.JSON(), nullable=False, server_default="{}"),
        sa.UniqueConstraint("fingerprint", name="uq_kubernetes_conditions_fingerprint"),
        sa.CheckConstraint("status IN ('ACTIVE','RESOLVED','SUPPRESSED')", name="ck_kubernetes_condition_status"),
        sa.CheckConstraint("occurrence_count >= 1", name="ck_kubernetes_condition_occurrence_count"),
    )
    op.create_index("ix_kubernetes_conditions_status", "kubernetes_conditions", ["status"])
    op.create_index("ix_kubernetes_conditions_incident_id", "kubernetes_conditions", ["incident_id"])
    op.create_index("ix_kubernetes_conditions_status_last_seen", "kubernetes_conditions", ["status", "last_seen"])
    op.create_index("ix_kubernetes_conditions_cluster_status", "kubernetes_conditions", ["cluster_id", "status"])

    op.create_table(
        "remediation_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_action", sa.String(40), nullable=False),
        sa.Column("action_parameters", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("policy_decision", sa.String(32), nullable=False),
        sa.Column("policy_reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("decided_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requester_reason", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("remediation_action_id", sa.String(36), sa.ForeignKey("healing_actions.id", ondelete="SET NULL"), nullable=True),
        sa.UniqueConstraint("remediation_action_id", name="uq_remediation_approval_action_id"),
        sa.CheckConstraint("decision IN ('PENDING','APPROVED','REJECTED','EXPIRED')", name="ck_remediation_approval_decision"),
        sa.CheckConstraint("requested_action IN ('restart_deployment','scale_deployment')", name="ck_remediation_approval_action"),
    )
    op.create_index("ix_remediation_approvals_incident_id", "remediation_approvals", ["incident_id"])
    op.create_index("ix_remediation_approvals_requested_by", "remediation_approvals", ["requested_by"])
    op.create_index("ix_remediation_approvals_decision", "remediation_approvals", ["decision"])
    op.create_index("ix_remediation_approvals_expires_at", "remediation_approvals", ["expires_at"])
    op.create_index("ix_remediation_approvals_decision_expiration", "remediation_approvals", ["decision", "expires_at"])


def downgrade() -> None:
    op.drop_index("ix_remediation_approvals_decision_expiration", table_name="remediation_approvals")
    op.drop_index("ix_remediation_approvals_expires_at", table_name="remediation_approvals")
    op.drop_index("ix_remediation_approvals_decision", table_name="remediation_approvals")
    op.drop_index("ix_remediation_approvals_requested_by", table_name="remediation_approvals")
    op.drop_index("ix_remediation_approvals_incident_id", table_name="remediation_approvals")
    op.drop_table("remediation_approvals")
    op.drop_index("ix_kubernetes_conditions_status_last_seen", table_name="kubernetes_conditions")
    op.drop_index("ix_kubernetes_conditions_cluster_status", table_name="kubernetes_conditions")
    op.drop_index("ix_kubernetes_conditions_incident_id", table_name="kubernetes_conditions")
    op.drop_index("ix_kubernetes_conditions_status", table_name="kubernetes_conditions")
    op.drop_table("kubernetes_conditions")
