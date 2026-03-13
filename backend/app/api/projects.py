"""Project Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_org, authorize_project
from app.models.models import User, Project, ProjectMember
from app.schemas.schemas import ProjectCreate, ProjectResponse

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=list[ProjectResponse])
async def list_projects(org_id: UUID | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    q = select(Project).order_by(Project.created_at.desc())
    if org_id:
        q = q.where(Project.org_id == org_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(org_id: UUID, data: ProjectCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = Project(**data.model_dump(), org_id=org_id, created_by=user.id)
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_project(project_id, user, db)
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_project(project_id, user, db)
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(project)
    await db.commit()


@router.post("/{project_id}/members", status_code=201)
async def add_member(project_id: UUID, user_id: UUID, role: str = "tester", user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    member = ProjectMember(project_id=project_id, user_id=user_id, role=role)
    db.add(member)
    await db.commit()
    return {"status": "added"}


@router.delete("/{project_id}/members/{user_id}", status_code=204)
async def remove_member(project_id: UUID, user_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id)
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(member)
    await db.commit()
