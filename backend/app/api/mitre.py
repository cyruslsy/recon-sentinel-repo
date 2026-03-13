"""MITRE ATT&CK Routes — Technique reference and scan heatmap"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan
from app.models.models import User, MitreTechnique, MitreFindingCount
from app.schemas.schemas import MitreTechniqueResponse, MitreHeatmapItem, MitreHeatmapResponse

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/techniques", response_model=list[MitreTechniqueResponse])
async def list_techniques(tactic_id: str | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """List all MITRE ATT&CK techniques, optionally filtered by tactic."""
    q = select(MitreTechnique)
    if tactic_id:
        q = q.where(MitreTechnique.tactic_ids.any(tactic_id))
    q = q.order_by(MitreTechnique.id)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueResponse)
async def get_technique(technique_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    tech = await db.get(MitreTechnique, technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found")
    return tech


@router.get("/heatmap/{scan_id}", response_model=MitreHeatmapResponse)
async def get_heatmap(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_scan(scan_id, user, db)
    """Get MITRE ATT&CK heatmap data for a scan (from trigger-maintained counts)."""
    result = await db.execute(
        select(MitreFindingCount).where(MitreFindingCount.scan_id == scan_id).order_by(MitreFindingCount.technique_id)
    )
    counts = result.scalars().all()
    
    return MitreHeatmapResponse(
        scan_id=scan_id,
        techniques=[
            MitreHeatmapItem(
                technique_id=c.technique_id,
                finding_count=c.finding_count,
                critical_count=c.critical_count,
                high_count=c.high_count,
                medium_count=c.medium_count,
                max_severity=c.max_severity,
            )
            for c in counts
        ],
    )
