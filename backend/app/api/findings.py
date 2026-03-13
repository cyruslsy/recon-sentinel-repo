"""Findings Routes — with P1 bulk actions, filtering, and MITRE querying"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, any_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan, authorize_finding
from app.models.models import User, Finding
from app.models.enums import FindingSeverity, FindingType
from app.schemas.schemas import FindingResponse, FindingBrief, FindingUpdate, FindingBulkAction

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=list[FindingBrief])
async def list_findings(
    scan_id: UUID,
    severity: FindingSeverity | None = None,
    finding_type: FindingType | None = None,
    mitre_technique: str | None = None,
    is_false_positive: bool | None = None,
    tag: str | None = None,
    search: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List findings with comprehensive filtering. Max 200 per page."""
    await authorize_scan(scan_id, user, db)
    base_q = select(Finding).where(Finding.scan_id == scan_id)
    
    if severity:
        base_q = base_q.where(Finding.severity == severity)
    if finding_type:
        base_q = base_q.where(Finding.finding_type == finding_type)
    if mitre_technique:
        base_q = base_q.where(Finding.mitre_technique_ids.any(mitre_technique))
    if is_false_positive is not None:
        base_q = base_q.where(Finding.is_false_positive == is_false_positive)
    if tag:
        base_q = base_q.where(Finding.tags.any(tag))
    if search:
        # Escape LIKE wildcards to prevent pattern injection
        safe_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        base_q = base_q.where(Finding.value.ilike(f"%{safe_search}%") | Finding.detail.ilike(f"%{safe_search}%"))
    
    q = base_q.order_by(Finding.severity, Finding.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/stats")
async def finding_stats(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Aggregate stats for dashboard: count by severity, type, MITRE technique."""
    await authorize_scan(scan_id, user, db)
    result = await db.execute(
        select(
            Finding.severity,
            func.count(Finding.id).label("count")
        ).where(
            Finding.scan_id == scan_id,
            Finding.is_false_positive == False  # noqa: E712
        ).group_by(Finding.severity)
    )
    severity_counts = {row.severity.value: row.count for row in result.all()}
    
    result2 = await db.execute(
        select(
            Finding.finding_type,
            func.count(Finding.id).label("count")
        ).where(Finding.scan_id == scan_id, Finding.is_false_positive == False).group_by(Finding.finding_type)  # noqa: E712
    )
    type_counts = {row.finding_type.value: row.count for row in result2.all()}
    
    return {"severity": severity_counts, "type": type_counts}


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    finding = await authorize_finding(finding_id, user, db)
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(finding_id: UUID, data: FindingUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Update finding: mark false positive, add notes, assign to user, update tags."""
    finding = await authorize_finding(finding_id, user, db)
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(finding, key, value)
    
    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/bulk", response_model=dict)
async def bulk_action(data: FindingBulkAction, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """P1: Bulk actions on multiple findings."""
    logger.info(f"Bulk action '{data.action}' on {len(data.finding_ids)} findings by user {user.id}")
    findings = []
    authorized_scans = set()  # Cache scan auth checks
    for fid in data.finding_ids:
        f = await db.get(Finding, fid)
        if f:
            # Verify user has access to this finding's scan
            if f.scan_id not in authorized_scans:
                try:
                    await authorize_scan(f.scan_id, user, db)
                    authorized_scans.add(f.scan_id)
                except HTTPException:
                    continue  # Skip findings the user can't access
            findings.append(f)
    
    if not findings:
        raise HTTPException(status_code=404, detail="No valid findings found")
    
    count = 0
    for f in findings:
        if data.action == "mark_false_positive":
            f.is_false_positive = True
            count += 1
        elif data.action == "unmark_false_positive":
            f.is_false_positive = False
            count += 1
        elif data.action == "add_tag" and data.value:
            if data.value not in (f.tags or []):
                f.tags = (f.tags or []) + [data.value]
                count += 1
        elif data.action == "remove_tag" and data.value:
            if data.value in (f.tags or []):
                f.tags = [t for t in f.tags if t != data.value]
                count += 1
        elif data.action == "assign_to" and data.value:
            f.assigned_to = data.value
            count += 1
        elif data.action == "add_note" and data.value:
            f.user_notes = (f.user_notes or "") + "\n" + str(data.value)
            count += 1
    
    await db.commit()
    return {"action": data.action, "affected": count, "total_requested": len(data.finding_ids)}
