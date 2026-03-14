"""Scope Control Routes — P0 Feature
3-level enforcement: API → Orchestrator → Agent
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_project
from app.models.models import User, ScopeDefinition, ScopeViolation, Scan, Target
from app.schemas.schemas import (
    ScopeItemCreate, ScopeItemResponse, ScopeItemUpdate,
    ScopeViolationResponse, ScopeCheckRequest, ScopeCheckResponse,
)

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{project_id}", response_model=list[ScopeItemResponse])
async def list_scope_items(project_id: UUID, status: str | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_project(project_id, user, db)
    """List all scope definitions for a project, optionally filtered by status."""
    q = select(ScopeDefinition).where(ScopeDefinition.project_id == project_id)
    if status:
        q = q.where(ScopeDefinition.status == status)
    q = q.order_by(ScopeDefinition.status, ScopeDefinition.created_at)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/{project_id}", response_model=ScopeItemResponse, status_code=201)
async def add_scope_item(project_id: UUID, data: ScopeItemCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_project(project_id, user, db)
    """Add a domain, IP, CIDR, or regex to scope (in-scope or excluded)."""
    item = ScopeDefinition(**data.model_dump(), project_id=project_id, added_by=user.id)
    db.add(item)
    await db.commit()
    await db.refresh(item)
    logger.info(f"Scope item added: {data.item_value} to project {project_id}")
    return item


@router.patch("/{item_id}", response_model=ScopeItemResponse)
async def update_scope_item(item_id: UUID, data: ScopeItemUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Toggle a scope item between in_scope and out_of_scope."""
    from app.core.authorization import authorize_scope_item
    item = await authorize_scope_item(item_id, user, db)
    item.status = data.status
    await db.commit()
    await db.refresh(item)
    return item


@router.delete("/{item_id}", status_code=204)
async def delete_scope_item(item_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from app.core.authorization import authorize_scope_item
    item = await authorize_scope_item(item_id, user, db)
    await db.delete(item)
    await db.commit()


@router.post("/{project_id}/check", response_model=ScopeCheckResponse)
async def check_scope(project_id: UUID, data: ScopeCheckRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Check if a target value is in scope. Uses the is_in_scope() database function."""
    await authorize_project(project_id, user, db)
    result = await db.execute(
        text("SELECT is_in_scope(:project_id, :target)"),
        {"project_id": str(project_id), "target": data.target_value}
    )
    is_in = result.scalar()
    return ScopeCheckResponse(target_value=data.target_value, is_in_scope=is_in or False)


@router.get("/{project_id}/violations", response_model=list[ScopeViolationResponse])
async def list_violations(project_id: UUID, scan_id: UUID | None = None, limit: int = 50, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """List scope violations (blocked requests) for audit trail."""
    await authorize_project(project_id, user, db)
    q = (
        select(ScopeViolation)
        .join(Scan, ScopeViolation.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(Target.project_id == project_id)
        .order_by(ScopeViolation.blocked_at.desc())
        .limit(limit)
    )
    if scan_id:
        q = q.where(ScopeViolation.scan_id == scan_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/{project_id}/import/hackerone")
async def import_hackerone_scope(project_id: UUID, program_handle: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import scope from a HackerOne program's public structured scope."""
    await authorize_project(project_id, user, db)
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://hackerone.com/graphql",
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json={
                "query": "query($handle: String!) { team(handle: $handle) { structured_scopes(first: 100) { edges { node { asset_identifier, asset_type, eligible_for_submission } } } } }",
                "variables": {"handle": program_handle},
            },
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"HackerOne API returned {resp.status_code}")

            data = resp.json()
            scopes = data.get("data", {}).get("team", {}).get("structured_scopes", {}).get("edges", [])
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"HackerOne API unreachable: {e}")

    created = 0
    for edge in scopes:
        node = edge.get("node", {})
        asset = node.get("asset_identifier", "")
        asset_type = node.get("asset_type", "").lower()
        eligible = node.get("eligible_for_submission", False)

        if not asset:
            continue

        item_type = "domain" if "url" in asset_type or "domain" in asset_type else "ip" if "cidr" in asset_type else "domain"
        status = "in_scope" if eligible else "out_of_scope"

        scope_item = ScopeDefinition(
            project_id=project_id,
            item_type=item_type,
            item_value=asset,
            status=status,
        )
        db.add(scope_item)
        created += 1

    await db.commit()
    logger.info(f"Imported {created} scope items from HackerOne/{program_handle}")
    return {"status": "imported", "source": "hackerone", "program": program_handle, "items_created": created}


@router.post("/{project_id}/import/bugcrowd")
async def import_bugcrowd_scope(project_id: UUID, program_slug: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import scope from a Bugcrowd program's public target groups."""
    await authorize_project(project_id, user, db)
    import httpx
    import re as _re

    # Sanitize slug — allow only alphanumeric, hyphens, underscores
    if not _re.match(r"^[a-zA-Z0-9_-]+$", program_slug):
        raise HTTPException(status_code=400, detail="Invalid program slug — alphanumeric, hyphens, underscores only")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://bugcrowd.com/{program_slug}.json",
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Bugcrowd returned {resp.status_code}")
            data = resp.json()
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Bugcrowd API unreachable: {e}")

    created = 0
    targets = data.get("target_groups", [])
    for group in targets:
        for target in group.get("targets", []):
            name = target.get("name", "")
            category = target.get("category", "").lower()
            in_scope = group.get("in_scope", True)

            if not name:
                continue

            item_type = "domain" if "website" in category or "api" in category else "ip" if "network" in category else "domain"
            scope_item = ScopeDefinition(
                project_id=project_id,
                item_type=item_type,
                item_value=name,
                status="in_scope" if in_scope else "out_of_scope",
            )
            db.add(scope_item)
            created += 1

    await db.commit()
    logger.info(f"Imported {created} scope items from Bugcrowd/{program_slug}")
    return {"status": "imported", "source": "bugcrowd", "program": program_slug, "items_created": created}
