"""Add pentester triage fields to findings table

Revision ID: 0005
Revises: 0004
Create Date: 2026-03-13

Adds verification_status, severity_override, and severity_override_reason
columns to support the pentester finding triage workflow:
  - verification_status: unverified → confirmed → false_positive → remediated
  - severity_override: allows pentester to override scanner-assigned severity
  - severity_override_reason: justification for the override
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("verification_status", sa.String(20), server_default="unverified"),
    )
    op.add_column(
        "findings",
        sa.Column("severity_override", sa.String(20), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("severity_override_reason", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "severity_override_reason")
    op.drop_column("findings", "severity_override")
    op.drop_column("findings", "verification_status")
