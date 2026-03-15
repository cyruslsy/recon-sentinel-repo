"""0009 — Add remediation column to findings table

Supports per-finding remediation guidance from agents and AI.
"""

from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "remediation")
