"""enable row-level security

Revision ID: 0003_row_level_security
Revises: 0002_scope_function
"""

from alembic import op

revision = "0003_row_level_security"
down_revision = "0002_scope_function"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─── RLS on scans: users can only see scans they created or scans in their projects ───
    op.execute("ALTER TABLE scans ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE scans FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY scans_isolation ON scans
        USING (
            created_by = current_setting('app.current_user_id')::uuid
            OR target_id IN (
                SELECT t.id FROM targets t
                JOIN project_members pm ON pm.project_id = t.project_id
                WHERE pm.user_id = current_setting('app.current_user_id')::uuid
            )
        );
    """)

    # ─── RLS on findings: inherit from scan access ────────────────────────────────────────
    op.execute("ALTER TABLE findings ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE findings FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY findings_isolation ON findings
        USING (
            scan_id IN (
                SELECT s.id FROM scans s WHERE
                    s.created_by = current_setting('app.current_user_id')::uuid
                    OR s.target_id IN (
                        SELECT t.id FROM targets t
                        JOIN project_members pm ON pm.project_id = t.project_id
                        WHERE pm.user_id = current_setting('app.current_user_id')::uuid
                    )
            )
        );
    """)

    # ─── RLS on agent_runs: inherit from scan ─────────────────────────────────────────────
    op.execute("ALTER TABLE agent_runs ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE agent_runs FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY agent_runs_isolation ON agent_runs
        USING (
            scan_id IN (
                SELECT s.id FROM scans s WHERE
                    s.created_by = current_setting('app.current_user_id')::uuid
                    OR s.target_id IN (
                        SELECT t.id FROM targets t
                        JOIN project_members pm ON pm.project_id = t.project_id
                        WHERE pm.user_id = current_setting('app.current_user_id')::uuid
                    )
            )
        );
    """)

    # ─── RLS on reports: inherit from scan ────────────────────────────────────────────────
    op.execute("ALTER TABLE reports ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE reports FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY reports_isolation ON reports
        USING (
            scan_id IN (
                SELECT s.id FROM scans s WHERE
                    s.created_by = current_setting('app.current_user_id')::uuid
                    OR s.target_id IN (
                        SELECT t.id FROM targets t
                        JOIN project_members pm ON pm.project_id = t.project_id
                        WHERE pm.user_id = current_setting('app.current_user_id')::uuid
                    )
            )
        );
    """)

    # ─── RLS on credential_leaks: inherit from scan ───────────────────────────────────────
    op.execute("ALTER TABLE credential_leaks ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE credential_leaks FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY credential_leaks_isolation ON credential_leaks
        USING (
            scan_id IN (
                SELECT s.id FROM scans s WHERE
                    s.created_by = current_setting('app.current_user_id')::uuid
                    OR s.target_id IN (
                        SELECT t.id FROM targets t
                        JOIN project_members pm ON pm.project_id = t.project_id
                        WHERE pm.user_id = current_setting('app.current_user_id')::uuid
                    )
            )
        );
    """)

    # ─── Bypass policy for the API service role (connection pooler) ────────────────────────
    # The FastAPI app connects as 'sentinel' user. RLS policies above use
    # current_setting('app.current_user_id') which must be SET before each query.
    # The app sets this in middleware. Celery workers use a superuser bypass role.
    op.execute("""
    DO $$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_worker') THEN
            CREATE ROLE sentinel_worker NOLOGIN;
        END IF;
    END $$;
    """)
    op.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO sentinel_worker;")
    op.execute("ALTER ROLE sentinel_worker BYPASSRLS;")


def downgrade() -> None:
    for table in ("scans", "findings", "agent_runs", "reports", "credential_leaks"):
        op.execute(f"DROP POLICY IF EXISTS {table}_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    op.execute("DROP ROLE IF EXISTS sentinel_worker;")
