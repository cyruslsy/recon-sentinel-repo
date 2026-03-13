"""Scope Control Routes — P0 Feature
3-level enforcement: API → Orchestrator → Agent
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, ScopeDefinition, ScopeViolation
from app.schemas.schemas import (
    ScopeItemCreate, ScopeItemResponse, ScopeItemUpdate,
    ScopeViolationResponse, ScopeCheckRequest, ScopeCheckResponse,
)

router = APIRouter()


@router.get("/{project_id}", response_model=list[ScopeItemResponse])
async def list_scope_items(project_id: UUID, status: str | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """List all scope definitions for a project, optionally filtered by status."""
    q = select(ScopeDefinition).where(ScopeDefinition.project_id == project_id)
    if status:
        q = q.where(ScopeDefinition.status == status)
    q = q.order_by(ScopeDefinition.status, ScopeDefinition.created_at)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/{project_id}", response_model=ScopeItemResponse, status_code=201)
async def add_scope_item(project_id: UUID, data: ScopeItemCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Add a domain, IP, CIDR, or regex to scope (in-scope or excluded)."""
    item = ScopeDefinition(**data.model_dump(), project_id=project_id)
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item


@router.patch("/{item_id}", response_model=ScopeItemResponse)
async def update_scope_item(item_id: UUID, data: ScopeItemUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Toggle a scope item between in_scope and out_of_scope."""
    item = await db.get(ScopeDefinition, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scope item not found")
    item.status = data.status
    await db.commit()
    await db.refresh(item)
    return item


@router.delete("/{item_id}", status_code=204)
async def delete_scope_item(item_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    item = await db.get(ScopeDefinition, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scope item not found")
    await db.delete(item)
    await db.commit()


@router.post("/{project_id}/check", response_model=ScopeCheckResponse)
async def check_scope(project_id: UUID, data: ScopeCheckRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Check if a target value is in scope. Uses the is_in_scope() database function."""
    result = await db.execute(
        text("SELECT is_in_scope(:project_id, :target)"),
        {"project_id": str(project_id), "target": data.target_value}
    )
    is_in = result.scalar()
    return ScopeCheckResponse(target_value=data.target_value, is_in_scope=is_in or False)


@router.get("/{project_id}/violations", response_model=list[ScopeViolationResponse])
async def list_violations(project_id: UUID, scan_id: UUID | None = None, limit: int = 50, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """List scope violations (blocked requests) for audit trail."""
    q = select(ScopeViolation).order_by(ScopeViolation.blocked_at.desc()).limit(limit)
    if scan_id:
        q = q.where(ScopeViolation.scan_id == scan_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/{project_id}/import/hackerone")
async def import_hackerone_scope(project_id: UUID, program_handle: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import scope from a HackerOne program."""
    # TODO: Call HackerOne API, parse scope, create ScopeDefinition entries
    return {"status": "import_queued", "source": "hackerone", "program": program_handle}


@router.post("/{project_id}/import/bugcrowd")
async def import_bugcrowd_scope(project_id: UUID, program_slug: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import scope from a Bugcrowd program."""
    # TODO: Call Bugcrowd API
    return {"status": "import_queued", "source": "bugcrowd", "program": program_slug}
