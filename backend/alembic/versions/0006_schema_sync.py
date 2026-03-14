"""0006 — Schema sync v1.2: new columns, enum additions, value expansion

Changes:
- AgentRun: add target_host (fan-out subdomain tracking), celery_task_id (task revocation)
- Finding.value + ScanDiffItem.value: expand VARCHAR(1000) → VARCHAR(2000)
- ScanPhase enum: add 'replan'
- ScanProfile enum: add 'bounty'
- AgentStatus enum: add 'error_resolved'
- FindingType enum: add 10 new values (cloud_asset, js_secret, api_endpoint, dns, screenshot, waf, waf_detection, historical, tech_stack, github_leak)

Note: PostgreSQL requires ALTER TYPE ... ADD VALUE to be run outside a transaction.
Alembic handles this with autocommit mode.
"""

from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    # ── New columns ──────────────────────────────────────────────
    op.add_column("agent_runs", sa.Column("target_host", sa.String(500), nullable=True))
    op.add_column("agent_runs", sa.Column("celery_task_id", sa.String(255), nullable=True))

    # ── Column type expansion ────────────────────────────────────
    op.alter_column("findings", "value", type_=sa.String(2000), existing_type=sa.String(1000))
    op.alter_column("scan_diff_items", "value", type_=sa.String(2000), existing_type=sa.String(1000))

    # ── Enum type additions ──────────────────────────────────────
    # PostgreSQL ALTER TYPE ADD VALUE cannot run inside a transaction block.
    # We use op.execute with the connection's execution_options.
    # Each ADD VALUE is idempotent — IF NOT EXISTS prevents errors on re-run.

    # ScanPhase: add 'replan' between gate_2 and vuln
    op.execute("ALTER TYPE scan_phase ADD VALUE IF NOT EXISTS 'replan'")

    # ScanProfile: add 'bounty'
    op.execute("ALTER TYPE scan_profile ADD VALUE IF NOT EXISTS 'bounty'")

    # AgentStatus: add 'error_resolved'
    op.execute("ALTER TYPE agent_status ADD VALUE IF NOT EXISTS 'error_resolved'")

    # FindingType: add new values for agents added in R9-R11
    new_finding_types = [
        "cloud_asset", "js_secret", "api_endpoint", "dns", "screenshot",
        "waf", "waf_detection", "historical", "tech_stack", "github_leak",
    ]
    for ft in new_finding_types:
        op.execute(f"ALTER TYPE finding_type_enum ADD VALUE IF NOT EXISTS '{ft}'")


def downgrade():
    # Column changes are reversible
    op.alter_column("scan_diff_items", "value", type_=sa.String(1000), existing_type=sa.String(2000))
    op.alter_column("findings", "value", type_=sa.String(1000), existing_type=sa.String(2000))
    op.drop_column("agent_runs", "celery_task_id")
    op.drop_column("agent_runs", "target_host")
    # Note: PostgreSQL does not support removing values from enum types.
    # The enum additions are permanent. To fully downgrade, recreate the types.
