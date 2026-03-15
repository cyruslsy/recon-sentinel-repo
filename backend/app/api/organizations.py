"""Organization Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_org
from app.models.models import User, Organization
from app.schemas.schemas import OrganizationCreate, OrganizationResponse

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=list[OrganizationResponse])
async def list_organizations(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if user.role and user.role.value == "admin":
        q = select(Organization).order_by(Organization.created_at.desc())
    else:
        from app.models.models import Project, ProjectMember
        # Orgs where user is a member of any project, or user created the org
        member_orgs = (
            select(Project.org_id)
            .join(ProjectMember, ProjectMember.project_id == Project.id)
            .where(ProjectMember.user_id == user.id)
        )
        q = select(Organization).where(
            (Organization.id.in_(member_orgs)) | (Organization.created_by == user.id)
        ).order_by(Organization.created_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=OrganizationResponse, status_code=201)
async def create_organization(data: OrganizationCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    org = Organization(**data.model_dump(), created_by=user.id)
    db.add(org)
    await db.flush()
    await db.refresh(org)
    return org


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(org_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await authorize_org(org_id, user, db)


@router.delete("/{org_id}", status_code=204)
async def delete_organization(org_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    org = await authorize_org(org_id, user, db)
    await db.delete(org)
    await db.commit()
