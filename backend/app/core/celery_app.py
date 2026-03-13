"""
Recon Sentinel — Celery Application
Task queue with Redis broker, per-agent queue routing,
and beat schedule for periodic tasks.
"""

from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()

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
    },
)

# Auto-discover tasks in app.agents and app.tasks packages
celery_app.autodiscover_tasks(["app.agents", "app.tasks"])
