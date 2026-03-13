"""Project Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import Project, ProjectMember
from app.schemas.schemas import ProjectCreate, ProjectResponse

router = APIRouter()


@router.get("/", response_model=list[ProjectResponse])
async def list_projects(org_id: UUID | None = None, db: AsyncSession = Depends(get_db)):
    q = select(Project).order_by(Project.created_at.desc())
    if org_id:
        q = q.where(Project.org_id == org_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(org_id: UUID, data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(**data.model_dump(), org_id=org_id, created_by="00000000-0000-0000-0000-000000000000")
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: UUID, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: UUID, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(project)
    await db.commit()


@router.post("/{project_id}/members", status_code=201)
async def add_member(project_id: UUID, user_id: UUID, role: str = "tester", db: AsyncSession = Depends(get_db)):
    member = ProjectMember(project_id=project_id, user_id=user_id, role=role)
    db.add(member)
    await db.commit()
    return {"status": "added"}


@router.delete("/{project_id}/members/{user_id}", status_code=204)
async def remove_member(project_id: UUID, user_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id)
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(member)
    await db.commit()
