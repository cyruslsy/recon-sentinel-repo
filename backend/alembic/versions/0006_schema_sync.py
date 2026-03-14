"""0006 — Schema sync: AgentRun.target_host, AgentRun.celery_task_id, Finding.value expansion

Fixes:
- AgentRun: add target_host (fan-out subdomain tracking), celery_task_id (task revocation)
- Finding.value: expand from VARCHAR(1000) to VARCHAR(2000) for long Nuclei URLs
"""

from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    # AgentRun: add target_host for per-subdomain fan-out tracking
    op.add_column("agent_runs", sa.Column("target_host", sa.String(500), nullable=True))
    # AgentRun: add celery_task_id for task revocation on scan stop
    op.add_column("agent_runs", sa.Column("celery_task_id", sa.String(255), nullable=True))
    # Finding.value: expand from 1000 to 2000 chars (Nuclei URLs can be long)
    op.alter_column("findings", "value", type_=sa.String(2000), existing_type=sa.String(1000))
    # ScanDiffItem.value: match Finding.value expansion
    op.alter_column("scan_diff_items", "value", type_=sa.String(2000), existing_type=sa.String(1000))


def downgrade():
    op.alter_column("scan_diff_items", "value", type_=sa.String(1000), existing_type=sa.String(2000))
    op.alter_column("findings", "value", type_=sa.String(1000), existing_type=sa.String(2000))
    op.drop_column("agent_runs", "celery_task_id")
    op.drop_column("agent_runs", "target_host")
