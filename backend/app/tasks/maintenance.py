"""
Recon Sentinel — Maintenance Tasks
Periodic tasks run by Celery Beat.
"""

import logging
from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.maintenance.check_api_rate_limits")
def check_api_rate_limits():
    """Check if any paused agents can resume (rate limit windows expired)."""
    # TODO: Week 5 — query agent_runs with status=waiting_for_api,
    # check if rate limit window expired, resume via distributed lock
    pass


@celery_app.task(name="app.tasks.maintenance.cleanup_expired_tokens")
def cleanup_expired_tokens():
    """Belt-and-suspenders cleanup. Redis TTL handles actual expiry."""
    logger.debug("Token cleanup — Redis TTL handles this, nothing to do")


@celery_app.task(name="app.tasks.maintenance.refresh_target_context")
def refresh_target_context():
    """Refresh WHOIS/DNS data for active targets."""
    # TODO: Week 5 — query targets with recent scans,
    # re-resolve DNS, update whois_data, tech_stack
    logger.debug("Target context refresh — not yet implemented")
