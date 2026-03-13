"""add findings dedup constraint

Revision ID: 0004_findings_dedup
Revises: 0003_row_level_security
"""

from alembic import op

revision = "0004_findings_dedup"
down_revision = "0003_row_level_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Unique constraint on (scan_id, fingerprint) — prevents duplicate findings
    # when fan-out sends the same agent to two subdomains that resolve to the same IP.
    # NULL fingerprints are allowed (PostgreSQL treats each NULL as unique).
    op.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_scan_fingerprint
    ON findings (scan_id, fingerprint)
    WHERE fingerprint IS NOT NULL;
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_findings_scan_fingerprint;")
