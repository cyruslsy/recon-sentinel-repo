"""Organization Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.models import Organization
from app.schemas.schemas import OrganizationCreate, OrganizationResponse

router = APIRouter()


@router.get("/", response_model=list[OrganizationResponse])
async def list_organizations(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Organization).order_by(Organization.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=OrganizationResponse, status_code=201)
async def create_organization(data: OrganizationCreate, db: AsyncSession = Depends(get_db)):
    org = Organization(**data.model_dump(), created_by="00000000-0000-0000-0000-000000000000")  # TODO: from auth
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(org_id: UUID, db: AsyncSession = Depends(get_db)):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.delete("/{org_id}", status_code=204)
async def delete_organization(org_id: UUID, db: AsyncSession = Depends(get_db)):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    await db.delete(org)
    await db.commit()
