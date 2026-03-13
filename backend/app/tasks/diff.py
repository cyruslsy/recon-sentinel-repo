"""
Recon Sentinel — Scan Diff Engine
Compares findings between two scans of the same target.
Produces: new findings, removed findings, changed findings.
Generates AI summary of changes.

Used by:
  - POST /history/diff/{scan_id}/compute (manual trigger)
  - Orchestrator auto-diff on scan completion
  - Celery Beat scheduled re-scans
"""

import uuid
import json
import logging
from collections import defaultdict

from sqlalchemy import select, func

from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.core.llm import llm_call, LLMUnavailableError
from app.core.tz import utc_now
from app.models.models import Scan, Finding, ScanDiff, ScanDiffItem, Target
from app.models.enums import FindingSeverity

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.diff.compute_scan_diff")
def compute_scan_diff(scan_id: str, prev_scan_id: str):
    """Celery task: compute diff between two scans."""
    import asyncio
    return asyncio.run(_compute_diff(scan_id, prev_scan_id))


@celery_app.task(name="app.tasks.diff.auto_diff_on_complete")
def auto_diff_on_complete(scan_id: str):
    """Called when a scan completes — automatically diffs against last scan of same target."""
    import asyncio
    return asyncio.run(_auto_diff(scan_id))


async def _auto_diff(scan_id: str) -> dict | None:
    """Find the previous scan of the same target and compute diff."""
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return None

        # Find most recent completed scan of the same target (excluding this one)
        result = await db.execute(
            select(Scan.id)
            .where(
                Scan.target_id == scan.target_id,
                Scan.id != scan.id,
                Scan.status == "completed",
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        prev = result.scalar_one_or_none()
        if not prev:
            logger.info(f"No previous scan for target {scan.target_id} — skipping auto-diff")
            return None

    return await _compute_diff(scan_id, str(prev))


async def _compute_diff(scan_id: str, prev_scan_id: str) -> dict:
    """
    Core diff logic:
    1. Load findings from both scans
    2. Index by fingerprint (or value if no fingerprint)
    3. Compute new, removed, changed sets
    4. Create ScanDiff + ScanDiffItem records
    5. Generate AI summary of changes
    """
    scan_uuid = uuid.UUID(scan_id)
    prev_uuid = uuid.UUID(prev_scan_id)

    # ─── Check existing (short session) ───────────────────────
    async with AsyncSessionLocal() as db:
        existing = await db.execute(
            select(ScanDiff).where(
                ScanDiff.scan_id == scan_uuid,
                ScanDiff.prev_scan_id == prev_uuid,
            )
        )
        if existing.scalar_one_or_none():
            logger.info(f"Diff already exists for {scan_id} vs {prev_scan_id}")
            return {"status": "already_computed"}

    # ─── Load findings (separate short sessions) ──────────────
    async with AsyncSessionLocal() as db:
        current_findings = await _load_findings(db, scan_uuid)

    async with AsyncSessionLocal() as db:
        previous_findings = await _load_findings(db, prev_uuid)

    # ─── Index by fingerprint ─────────────────────────────────
    current_map = _index_findings(current_findings)
    previous_map = _index_findings(previous_findings)

    current_keys = set(current_map.keys())
    previous_keys = set(previous_map.keys())

    new_keys = current_keys - previous_keys
    removed_keys = previous_keys - current_keys
    common_keys = current_keys & previous_keys

    # ─── Detect changes in common findings ────────────────────
    changed_keys = set()
    for key in common_keys:
        curr = current_map[key]
        prev = previous_map[key]
        if curr["severity"] != prev["severity"] or curr["detail"] != prev["detail"]:
            changed_keys.add(key)

    # ─── Build diff items ─────────────────────────────────────
    diff_items = []

    for key in new_keys:
        f = current_map[key]
        diff_items.append({
            "change_type": "new",
            "finding_type": f["finding_type"],
            "value": f["value"],
            "detail": f["detail"],
            "severity": f["severity"],
            "finding_id": f["id"],
        })

    for key in removed_keys:
        f = previous_map[key]
        diff_items.append({
            "change_type": "removed",
            "finding_type": f["finding_type"],
            "value": f["value"],
            "detail": f"Previously found, now absent: {f['detail'][:200]}",
            "severity": f["severity"],
            "finding_id": None,  # Finding is from previous scan
        })

    for key in changed_keys:
        curr = current_map[key]
        prev = previous_map[key]
        diff_items.append({
            "change_type": "changed",
            "finding_type": curr["finding_type"],
            "value": curr["value"],
            "detail": f"Changed: severity {prev['severity']}→{curr['severity']}. {curr['detail'][:200]}",
            "severity": curr["severity"],
            "finding_id": curr["id"],
        })

    # ─── Capture scan config snapshots ───────────────────────
    async with AsyncSessionLocal() as db:
        current_scan = await db.get(Scan, scan_uuid)
        prev_scan = await db.get(Scan, prev_uuid)
        config_snapshot = {
            "current": {
                "profile": current_scan.profile.value if current_scan and current_scan.profile else "unknown",
                "created_at": str(current_scan.created_at) if current_scan else None,
            },
            "previous": {
                "profile": prev_scan.profile.value if prev_scan and prev_scan.profile else "unknown",
                "created_at": str(prev_scan.created_at) if prev_scan else None,
            },
            "config_changed": bool(
                current_scan and prev_scan and
                (current_scan.profile.value if hasattr(current_scan.profile, 'value') else str(current_scan.profile))
                != (prev_scan.profile.value if hasattr(prev_scan.profile, 'value') else str(prev_scan.profile))
            ),
        }

    # ─── Count by category ────────────────────────────────────
    new_by_type = _count_by_type(new_keys, current_map)
    removed_by_type = _count_by_type(removed_keys, previous_map)

    # ─── Generate AI summary ──────────────────────────────────
    ai_summary = await _generate_diff_summary(
        scan_id, prev_scan_id,
        len(new_keys), len(removed_keys), len(changed_keys),
        new_by_type, removed_by_type, diff_items,
    )

    # ─── Save to database ─────────────────────────────────────
    async with AsyncSessionLocal() as db:
        diff = ScanDiff(
            scan_id=scan_uuid,
            prev_scan_id=prev_uuid,
            new_findings_count=len(new_keys),
            removed_findings_count=len(removed_keys),
            new_subdomains=new_by_type.get("subdomain", 0),
            removed_subdomains=removed_by_type.get("subdomain", 0),
            new_ports=new_by_type.get("port", 0),
            closed_ports=removed_by_type.get("port", 0),
            new_vulns=new_by_type.get("vulnerability", 0),
            resolved_vulns=removed_by_type.get("vulnerability", 0),
            new_credentials=new_by_type.get("credential", 0),
            ai_diff_summary=ai_summary,
            computed_at=utc_now(),
        )
        db.add(diff)
        await db.flush()

        for item in diff_items:
            di = ScanDiffItem(
                diff_id=diff.id,
                change_type=item["change_type"],
                finding_type=item["finding_type"],
                value=item["value"][:1000],
                detail=item["detail"][:2000] if item["detail"] else None,
                severity=item["severity"],
                finding_id=uuid.UUID(item["finding_id"]) if item["finding_id"] else None,
            )
            db.add(di)

        await db.commit()

    result = {
        "status": "computed",
        "new": len(new_keys),
        "removed": len(removed_keys),
        "changed": len(changed_keys),
        "total_diff_items": len(diff_items),
    }
    logger.info(f"Diff computed: {scan_id} vs {prev_scan_id} — {result}")
    return result


# ─── Helpers ──────────────────────────────────────────────────

async def _load_findings(db, scan_id: uuid.UUID) -> list[dict]:
    """Load all non-false-positive findings for a scan."""
    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id, Finding.is_false_positive == False)  # noqa
    )
    return [
        {
            "id": str(f.id),
            "fingerprint": f.fingerprint or f"{f.finding_type.value}:{f.value}",
            "finding_type": f.finding_type.value,
            "severity": f.severity.value if f.severity else "info",
            "value": f.value,
            "detail": f.detail or "",
        }
        for f in result.scalars().all()
    ]


def _index_findings(findings: list[dict]) -> dict[str, dict]:
    """Index findings by fingerprint for O(1) lookup. Handles duplicates with counter suffix."""
    index = {}
    for f in findings:
        key = f["fingerprint"]
        if key in index:
            # Duplicate fingerprint — append counter to make unique
            counter = 2
            while f"{key}#{counter}" in index:
                counter += 1
            key = f"{key}#{counter}"
        index[key] = f
    return index


def _count_by_type(keys: set[str], finding_map: dict[str, dict]) -> dict[str, int]:
    """Count findings by type for a set of fingerprint keys."""
    counts: dict[str, int] = defaultdict(int)
    for key in keys:
        f = finding_map.get(key)
        if f:
            counts[f["finding_type"]] += 1
    return dict(counts)


async def _generate_diff_summary(
    scan_id: str, prev_scan_id: str,
    new_count: int, removed_count: int, changed_count: int,
    new_by_type: dict, removed_by_type: dict,
    diff_items: list[dict],
) -> str:
    """Generate AI summary of scan differences."""
    # Collect high-severity changes for the prompt
    critical_changes = [
        d for d in diff_items
        if d["severity"] in ("critical", "high") and d["change_type"] == "new"
    ]

    prompt = (
        f"You are a security analyst comparing two recon scans of the same target.\n\n"
        f"Changes detected:\n"
        f"- New findings: {new_count} ({json.dumps(new_by_type)})\n"
        f"- Removed findings: {removed_count} ({json.dumps(removed_by_type)})\n"
        f"- Changed findings: {changed_count}\n\n"
    )

    if critical_changes:
        prompt += "New critical/high findings:\n"
        for c in critical_changes[:10]:
            prompt += f"  - [{c['severity']}] {c['value'][:80]}\n"
        prompt += "\n"

    prompt += (
        "Write a 2-3 sentence summary of what changed between scans. "
        "Focus on new risks and resolved issues. Be concise and actionable."
    )

    try:
        result = await llm_call(
            messages=[{"role": "user", "content": prompt}],
            model_tier="routing",
            task_type="summarize",
            scan_id=scan_id,
            max_tokens=300,
        )
        return result["content"]
    except LLMUnavailableError:
        return (
            f"{new_count} new findings, {removed_count} removed, {changed_count} changed. "
            f"New by type: {json.dumps(new_by_type)}. "
            f"Removed by type: {json.dumps(removed_by_type)}."
        )
