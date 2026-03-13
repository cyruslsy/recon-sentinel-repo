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
    pass


@celery_app.task(name="app.tasks.maintenance.cleanup_expired_tokens")
def cleanup_expired_tokens():
    """Belt-and-suspenders cleanup. Redis TTL handles actual expiry."""
    logger.debug("Token cleanup — Redis TTL handles this, nothing to do")


@celery_app.task(name="app.tasks.maintenance.refresh_target_context")
def refresh_target_context():
    """Refresh WHOIS/DNS data for active targets."""
    logger.debug("Target context refresh — not yet implemented")


@celery_app.task(name="app.tasks.maintenance.archive_old_scans")
def archive_old_scans():
    """Archive scans older than 90 days. Preserves findings but hides from default list."""
    import asyncio
    return asyncio.run(_archive_old_scans())


async def _archive_old_scans():
    from datetime import timedelta
    from sqlalchemy import select, update
    from app.core.database import AsyncSessionLocal
    from app.core.tz import utc_now
    from app.models.models import Scan
    from app.models.enums import ScanStatus

    cutoff = utc_now() - timedelta(days=90)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan.id).where(
                Scan.status == ScanStatus.COMPLETED,
                Scan.is_archived == False,  # noqa
                Scan.created_at < cutoff,
            )
        )
        old_ids = [r[0] for r in result.all()]
        if not old_ids:
            return {"archived": 0}

        await db.execute(
            update(Scan).where(Scan.id.in_(old_ids)).values(is_archived=True)
        )
        await db.commit()
        logger.info(f"Archived {len(old_ids)} scans older than 90 days")
        return {"archived": len(old_ids)}


@celery_app.task(name="app.tasks.maintenance.recover_stuck_scans")
def recover_stuck_scans():
    """Mark scans stuck in running/paused for >2 hours as error."""
    import asyncio
    return asyncio.run(_recover_stuck_scans())


async def _recover_stuck_scans():
    from datetime import timedelta
    from sqlalchemy import select, update
    from app.core.database import AsyncSessionLocal
    from app.core.tz import utc_now
    from app.models.models import Scan
    from app.models.enums import ScanStatus

    threshold = utc_now() - timedelta(hours=2)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan.id).where(
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PAUSED]),
                Scan.updated_at < threshold,
            )
        )
        stuck_ids = [r[0] for r in result.all()]
        if not stuck_ids:
            return {"recovered": 0}

        await db.execute(
            update(Scan)
            .where(Scan.id.in_(stuck_ids))
            .values(status=ScanStatus.ERROR, error_message="Scan timed out — no progress for 2+ hours.")
        )
        await db.commit()
        logger.warning(f"Recovered {len(stuck_ids)} stuck scans")
        return {"recovered": len(stuck_ids)}


@celery_app.task(name="app.tasks.maintenance.enrich_target_context")
def enrich_target_context(target_id: str, target_value: str):
    """Resolve DNS + basic WHOIS for a target. Updates target.context_data JSONB."""
    import asyncio
    return asyncio.run(_enrich_target(target_id, target_value))


async def _enrich_target(target_id: str, target_value: str):
    import socket
    import subprocess
    import uuid
    from sqlalchemy import update
    from app.core.database import AsyncSessionLocal
    from app.models.models import Target

    context = {"dns": {}, "whois": {}}

    # DNS resolution
    try:
        results = socket.getaddrinfo(target_value, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(addr[4][0] for addr in results))
        context["dns"]["resolved_ips"] = ips
        context["dns"]["record_count"] = len(ips)
    except socket.gaierror:
        context["dns"]["error"] = "DNS resolution failed"

    # MX records
    try:
        import subprocess
        result = subprocess.run(["dig", "+short", "MX", target_value], capture_output=True, text=True, timeout=10)
        mx_records = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        context["dns"]["mx_records"] = mx_records
    except Exception:
        pass

    # NS records
    try:
        result = subprocess.run(["dig", "+short", "NS", target_value], capture_output=True, text=True, timeout=10)
        ns_records = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        context["dns"]["ns_records"] = ns_records
    except Exception:
        pass

    # Save to DB
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Target).where(Target.id == uuid.UUID(target_id)).values(context_data=context)
        )
        await db.commit()

    logger.info(f"Target context enriched for {target_value}: {len(context.get('dns', {}).get('resolved_ips', []))} IPs")
    return context
