"""0007 — Add missing columns: ApiKey.created_by, Scan.error_message

Fixes:
- ApiKey.created_by: settings.py reads/writes this column but it didn't exist in the model
- Scan.error_message: resume_scan sets error_message=None but column was missing from Scan
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PgUUID

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    # ApiKey.created_by — FK to users.id
    # For existing rows, we need a default. Since this is a fresh deploy (no 0001_initial),
    # the table should be empty. If not, this will fail and needs manual backfill.
    op.add_column("api_keys", sa.Column("created_by", PgUUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_api_keys_created_by", "api_keys", "users",
        ["created_by"], ["id"],
    )
    # Make NOT NULL after backfill (safe for fresh deploys)
    op.alter_column("api_keys", "created_by", nullable=False)

    # Scan.error_message — nullable text for resume error tracking
    op.add_column("scans", sa.Column("error_message", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("scans", "error_message")
    op.drop_constraint("fk_api_keys_created_by", "api_keys", type_="foreignkey")
    op.drop_column("api_keys", "created_by")
