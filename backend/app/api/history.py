"""Scan History & Diff Routes — P0 Feature"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan
from app.models.models import User, ScanDiff, ScanDiffItem
from app.schemas.schemas import ScanDiffResponse, ScanDiffItemResponse

router = APIRouter()


@router.get("/diff/{scan_id}", response_model=ScanDiffResponse | None)
async def get_latest_diff(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get the diff between this scan and the most recent previous scan."""
    result = await db.execute(
        select(ScanDiff).where(ScanDiff.scan_id == scan_id).order_by(ScanDiff.computed_at.desc()).limit(1)
    )
    return result.scalar_one_or_none()


@router.get("/diff/{scan_id}/vs/{prev_scan_id}", response_model=ScanDiffResponse)
async def get_specific_diff(scan_id: UUID, prev_scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get diff between two specific scans."""
    result = await db.execute(
        select(ScanDiff).where(ScanDiff.scan_id == scan_id, ScanDiff.prev_scan_id == prev_scan_id)
    )
    diff = result.scalar_one_or_none()
    if not diff:
        raise HTTPException(status_code=404, detail="Diff not computed for this scan pair")
    return diff


@router.get("/diff/{diff_id}/items", response_model=list[ScanDiffItemResponse])
async def list_diff_items(
    diff_id: UUID, change_type: str | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """List individual changes in a diff."""
    q = select(ScanDiffItem).where(ScanDiffItem.diff_id == diff_id)
    if change_type:
        q = q.where(ScanDiffItem.change_type == change_type)
    q = q.order_by(ScanDiffItem.severity.desc(), ScanDiffItem.created_at)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/diff/{scan_id}/compute")
async def compute_diff(scan_id: UUID, prev_scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Trigger diff computation between two scans."""
    from app.tasks.diff import compute_scan_diff
    compute_scan_diff.delay(str(scan_id), str(prev_scan_id))
    return {"status": "diff_computation_queued", "scan_id": str(scan_id), "prev_scan_id": str(prev_scan_id)}
