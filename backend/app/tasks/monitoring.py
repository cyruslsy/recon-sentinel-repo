"""
Recon Sentinel — Continuous Monitoring
Re-scans targets on a configurable schedule.
Only re-scans if the most recent scan for a target is older than 24 hours.
Prevents exponential growth by skipping targets with recent or running scans.
"""

import logging
import uuid
from datetime import timedelta

from sqlalchemy import select, func, and_

from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.core.tz import utc_now
from app.models.models import Scan, Target
from app.models.enums import ScanStatus

logger = logging.getLogger(__name__)

# Minimum hours between re-scans of the same target
RESCAN_INTERVAL_HOURS = 24


@celery_app.task(name="app.tasks.monitoring.run_scheduled_rescans")
def run_scheduled_rescans():
    """Called by Celery Beat daily. Only re-scans targets with no scan in the last 24h."""
    import asyncio
    return asyncio.run(_run_scheduled_rescans())


async def _run_scheduled_rescans() -> dict:
    cutoff = utc_now() - timedelta(hours=RESCAN_INTERVAL_HOURS)

    async with AsyncSessionLocal() as db:
        # Subquery: targets that have a scan newer than cutoff (skip these)
        recent_scan_targets = (
            select(Scan.target_id)
            .where(Scan.created_at >= cutoff)
            .distinct()
            .subquery()
        )

        # Subquery: targets that have a running/queued scan right now (skip these)
        active_scan_targets = (
            select(Scan.target_id)
            .where(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.PAUSED]))
            .distinct()
            .subquery()
        )

        # Find targets eligible for re-scan:
        # - Have at least one completed, non-archived scan
        # - No scan in the last 24h
        # - No currently running scan
        result = await db.execute(
            select(
                Scan.target_id,
                Scan.profile,
                Target.target_value,
                Target.project_id,
            )
            .join(Target, Scan.target_id == Target.id)
            .where(
                Scan.status == ScanStatus.COMPLETED,
                Scan.is_archived == False,  # noqa
                Scan.target_id.notin_(select(recent_scan_targets.c.target_id)),
                Scan.target_id.notin_(select(active_scan_targets.c.target_id)),
            )
            .distinct(Scan.target_id)
            .order_by(Scan.target_id, Scan.created_at.desc())
        )
        targets = result.all()

    if not targets:
        logger.info("No targets eligible for re-scan")
        return {"rescanned": 0}

    rescanned = 0
    for target_id, profile, target_value, project_id in targets:
        try:
            async with AsyncSessionLocal() as db:
                new_scan = Scan(
                    target_id=target_id,
                    profile=profile,
                    status=ScanStatus.RUNNING,
                    created_by=uuid.UUID("00000000-0000-0000-0000-000000000000"),
                )
                db.add(new_scan)
                await db.commit()
                await db.refresh(new_scan)
                scan_id = str(new_scan.id)

            from app.tasks.orchestrator import start_scan
            start_scan.delay(
                scan_id,
                target_value,
                str(project_id),
                profile.value if hasattr(profile, "value") else str(profile),
            )
            rescanned += 1
            logger.info(f"Scheduled re-scan for {target_value}")
        except Exception as e:
            logger.error(f"Failed to schedule re-scan for {target_value}: {e}")

    logger.info(f"Scheduled {rescanned} re-scans")
    return {"rescanned": rescanned}
