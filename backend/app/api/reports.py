"""Report Generation Routes — P0 Feature"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan, authorize_report
from app.models.models import User, Report
from app.schemas.schemas import ReportCreate, ReportResponse

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=list[ReportResponse])
async def list_reports(scan_id: UUID | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if scan_id:
        await authorize_scan(scan_id, user, db)
        q = select(Report).where(Report.scan_id == scan_id).order_by(Report.generated_at.desc())
    else:
        # Scope to scans the user has access to via target→project→membership chain
        from app.models.models import Scan, Target, ProjectMember
        accessible_scans = (
            select(Scan.id)
            .join(Target, Scan.target_id == Target.id)
            .join(ProjectMember, ProjectMember.project_id == Target.project_id)
            .where(ProjectMember.user_id == user.id)
        )
        if user.role and user.role.value == "admin":
            q = select(Report).order_by(Report.generated_at.desc())
        else:
            q = select(Report).where(Report.scan_id.in_(accessible_scans)).order_by(Report.generated_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=ReportResponse, status_code=201)
async def generate_report(data: ReportCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Generate a new report. Dispatches LLM-powered report generation via Celery."""
    report = Report(
        **data.model_dump(),
        file_path="pending",
        generated_by=user.id,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Dispatch LLM-powered report generation
    from app.tasks.reports import generate_report as gen_task
    gen_task.delay(str(report.id))
    logger.info(f"Report generation queued for scan {data.scan_id}")

    return report


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await authorize_report(report_id, user, db)


@router.get("/{report_id}/download")
async def download_report(report_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Download the generated report file."""
    report = await authorize_report(report_id, user, db)
    if report.file_path == "pending":
        raise HTTPException(status_code=202, detail="Report is still generating")
    return FileResponse(report.file_path, filename=f"recon-sentinel-report.{report.format.value}")


@router.delete("/{report_id}", status_code=204)
async def delete_report(report_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    report = await authorize_report(report_id, user, db)
    await db.delete(report)
    await db.commit()
