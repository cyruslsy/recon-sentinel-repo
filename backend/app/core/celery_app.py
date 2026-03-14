"""
Recon Sentinel — Celery Application
Task queue with Redis broker, per-agent queue routing,
and beat schedule for periodic tasks.

IMPORTANT: This application requires the 'prefork' worker pool (Celery default).
Agent tasks use asyncio.run() to execute async code, which creates a new event loop
per task. This is INCOMPATIBLE with eventlet/gevent pools (which have their own
event loop). Always start workers with:
    celery -A app.core.celery_app worker --pool=prefork

If you see "RuntimeError: This event loop is already running", you are using
the wrong pool type.
"""

import logging

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_init

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


@worker_init.connect
def _check_pool_type(**kwargs):
    """Warn if worker is not using prefork pool (asyncio.run() requires it)."""
    import celery.concurrency
    pool_cls = getattr(celery.concurrency, "get_implementation", None)
    # Best-effort check — log a warning, don't crash
    try:
        import billiard  # noqa: F401 — only exists with prefork
    except ImportError:
        logger.warning(
            "billiard not found — Celery may not be using prefork pool. "
            "Agent tasks require prefork (asyncio.run() is incompatible with eventlet/gevent)."
        )

celery_app = Celery(
    "recon_sentinel",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Task execution
    task_acks_late=True,                 # Re-deliver if worker crashes
    worker_prefetch_multiplier=1,        # Fair scheduling
    task_reject_on_worker_lost=True,     # Re-queue on worker death
    task_track_started=True,             # Track running state

    # Task time limits — prevents permanently consumed worker slots
    # Default: 45min soft / 50min hard (covers most agents)
    # Vuln agents override this with task-level time_limit=5400 (90min)
    task_soft_time_limit=2700,           # 45 min soft limit (agents can catch and cleanup)
    task_time_limit=3000,                # 50 min hard kill (5 min grace after soft)

    # Worker memory protection — restart worker after processing N tasks
    # Prevents slow memory leaks from accumulating over days
    worker_max_tasks_per_child=50,       # Restart after 50 tasks
    worker_max_memory_per_child=512000,  # Restart if worker exceeds 512MB RSS (KB)

    # Broker connection resilience
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    broker_transport_options={
        "visibility_timeout": 3600,      # 1 hour — long-running agent tasks
        "socket_timeout": 10,
        "socket_connect_timeout": 10,
    },

    # Result expiry
    result_expires=3600,                 # 1 hour

    # Task routing — each agent type gets its own queue
    task_routes={
        "app.agents.subdomain.*":     {"queue": "subdomain"},
        "app.agents.port_scan.*":     {"queue": "port_scan"},
        "app.agents.web_recon.*":     {"queue": "web_recon"},
        "app.agents.dir_file.*":      {"queue": "dir_file"},
        "app.agents.vuln.*":          {"queue": "vuln"},
        "app.agents.cred_leak.*":     {"queue": "cred_leak"},
        "app.agents.threat_intel.*":  {"queue": "threat_intel"},
        "app.agents.osint.*":         {"queue": "osint"},
        "app.agents.email_sec.*":     {"queue": "email_sec"},
        "app.agents.ssl_tls.*":       {"queue": "ssl_tls"},
        "app.agents.waf.*":           {"queue": "waf"},
        "app.agents.cloud.*":         {"queue": "cloud"},
        "app.agents.historical.*":    {"queue": "historical"},
        "app.agents.js_analysis.*":   {"queue": "js_analysis"},
        "app.agents.wayback.*":       {"queue": "historical"},
        "app.agents.github_dork.*":   {"queue": "osint"},
        "app.agents.subdomain_takeover.*": {"queue": "vuln"},
        # Report generation and notifications on default queue
        "app.tasks.reports.*":        {"queue": "default"},
        "app.tasks.notifications.*":  {"queue": "default"},
    },

    # Beat schedule — periodic tasks
    beat_schedule={
        # Check for expired API rate limits every 60s
        "check-api-rate-limits": {
            "task": "app.tasks.maintenance.check_api_rate_limits",
            "schedule": 60.0,
        },
        # Clean expired token blacklist entries (Redis handles TTL, this is belt+suspenders)
        "cleanup-expired-tokens": {
            "task": "app.tasks.maintenance.cleanup_expired_tokens",
            "schedule": crontab(minute=0, hour="*/6"),  # Every 6 hours
        },
        # Refresh target context data (WHOIS/DNS)
        "refresh-target-context": {
            "task": "app.tasks.maintenance.refresh_target_context",
            "schedule": crontab(minute=0, hour=3),  # Daily at 3 AM
        },
        # Continuous monitoring: re-scan targets with monitoring enabled
        "scheduled-rescan": {
            "task": "app.tasks.monitoring.run_scheduled_rescans",
            "schedule": crontab(minute=0, hour=6),  # Daily at 6 AM
        },
        # Recover scans stuck in running/paused for >2 hours
        "recover-stuck-scans": {
            "task": "app.tasks.maintenance.recover_stuck_scans",
            "schedule": 900.0,  # Every 15 minutes
        },
        # Archive scans older than 90 days
        "archive-old-scans": {
            "task": "app.tasks.maintenance.archive_old_scans",
            "schedule": crontab(minute=0, hour=4),  # Daily at 4 AM
        },
    },
)

# Auto-discover tasks in app.agents and app.tasks packages
celery_app.autodiscover_tasks(["app.agents", "app.tasks"])
