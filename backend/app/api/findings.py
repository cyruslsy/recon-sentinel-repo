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


@router.get("/", response_model=list[FindingResponse])
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


@router.get("/export/csv")
async def export_findings_csv(
    scan_id: UUID,
    severity: FindingSeverity | None = None,
    finding_type: FindingType | None = None,
    is_false_positive: bool | None = None,
    limit: int = Query(default=5000, le=10000, ge=1),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export findings as CSV. Pentesters need this for client deliverables mid-engagement."""
    await authorize_scan(scan_id, user, db)

    q = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity, Finding.created_at).limit(limit)
    if severity:
        q = q.where(Finding.severity == severity)
    if finding_type:
        q = q.where(Finding.finding_type == finding_type)
    if is_false_positive is not None:
        q = q.where(Finding.is_false_positive == is_false_positive)

    result = await db.execute(q)
    findings = result.scalars().all()

    def _sanitize_csv_cell(value: str) -> str:
        """Prevent CSV injection: prefix cells starting with formula triggers."""
        if value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
            return f"'{value}"
        return value

    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Severity", "Type", "Value", "Detail", "MITRE Techniques",
        "Tags", "False Positive", "Verified", "Severity Override",
        "User Notes", "Created At",
    ])
    for f in findings:
        writer.writerow([
            str(f.id),
            f.severity.value if f.severity else "",
            f.finding_type.value if f.finding_type else "",
            _sanitize_csv_cell(f.value or ""),
            _sanitize_csv_cell((f.detail or "")[:500]),
            ", ".join(f.mitre_technique_ids or []),
            ", ".join(f.tags or []),
            "Yes" if f.is_false_positive else "No",
            getattr(f, "verification_status", "unverified") or "unverified",
            getattr(f, "severity_override", "") or "",
            _sanitize_csv_cell(getattr(f, "user_notes", "") or ""),
            str(f.created_at) if f.created_at else "",
        ])

    from fastapi.responses import StreamingResponse
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings-{scan_id}.csv"},
    )


@router.post("/{finding_id}/retest")
async def retest_finding(finding_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Retest a single finding — dispatches a targeted Nuclei run for just that template+target.
    Essential for post-remediation verification without rerunning the entire scan."""
    finding = await authorize_finding(finding_id, user, db)

    raw_data = finding.raw_data or {}
    template_id = raw_data.get("template_id")
    matched_at = raw_data.get("matched_at") or finding.value

    if not template_id:
        raise HTTPException(
            status_code=400,
            detail="Finding has no template_id in raw_data — cannot retest. Only Nuclei-generated findings support retest.",
        )

    # Dispatch a targeted Nuclei retest via Celery
    from app.core.celery_app import celery_app as _celery
    _celery.send_task(
        "app.tasks.maintenance.retest_single_finding",
        args=[str(finding_id), str(finding.scan_id), template_id, matched_at],
    )

    return {
        "status": "retest_queued",
        "finding_id": str(finding_id),
        "template": template_id,
        "target": matched_at,
    }
