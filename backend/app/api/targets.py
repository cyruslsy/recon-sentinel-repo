"""Target Routes — with P1 Target Context Panel"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_project, authorize_target
from app.models.models import User, Target, Scan
from app.schemas.schemas import TargetCreate, TargetResponse, TargetContextResponse

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=list[TargetResponse])
async def list_targets(project_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_project(project_id, user, db)
    result = await db.execute(
        select(Target).where(Target.project_id == project_id).order_by(Target.created_at.desc())
    )
    return result.scalars().all()


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(project_id: UUID, data: TargetCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_project(project_id, user, db)
    target = Target(**data.model_dump(), project_id=project_id, created_by=user.id)
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await authorize_target(target_id, user, db)


@router.get("/{target_id}/context", response_model=TargetContextResponse)
async def get_target_context(target_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """P1: Target Context Panel — WHOIS, ASN, CDN, tech stack, previous scans."""
    target = await authorize_target(target_id, user, db)
    
    scan_count = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.target_id == target_id)
    )
    
    return TargetContextResponse(
        resolved_ips=target.resolved_ips or [],
        asn_info=target.asn_info,
        cdn_detected=target.cdn_detected,
        registrar=target.registrar,
        domain_created=target.domain_created,
        domain_expires=target.domain_expires,
        nameservers=target.nameservers or [],
        tech_stack=target.tech_stack or [],
        previous_scan_count=scan_count.scalar() or 0,
    )


@router.post("/{target_id}/refresh-context")
async def refresh_target_context(target_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Trigger WHOIS/DNS/tech detection refresh for target context panel."""
    target = await authorize_target(target_id, user, db)

    # Dispatch async context enrichment
    from app.core.celery_app import celery_app as _celery
    _celery.send_task("app.tasks.maintenance.enrich_target_context", args=[str(target_id), target.target_value])

    return {"status": "context_refresh_queued", "target_id": str(target_id)}


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    target = await authorize_target(target_id, user, db)
    await db.delete(target)
    await db.commit()
