"""Report Generation Routes — P0 Feature"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import Report
from app.schemas.schemas import ReportCreate, ReportResponse

router = APIRouter()


@router.get("/", response_model=list[ReportResponse])
async def list_reports(scan_id: UUID | None = None, db: AsyncSession = Depends(get_db)):
    q = select(Report).order_by(Report.generated_at.desc())
    if scan_id:
        q = q.where(Report.scan_id == scan_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=ReportResponse, status_code=201)
async def generate_report(data: ReportCreate, db: AsyncSession = Depends(get_db)):
    """Generate a new report. Dispatches LLM-powered report generation via Celery."""
    report = Report(
        **data.model_dump(),
        file_path="pending",
        generated_by="00000000-0000-0000-0000-000000000000",  # TODO: from auth
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Dispatch LLM-powered report generation
    from app.tasks.reports import generate_report as gen_task
    gen_task.delay(str(report.id))

    return report


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: UUID, db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/download")
async def download_report(report_id: UUID, db: AsyncSession = Depends(get_db)):
    """Download the generated report file."""
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.file_path == "pending":
        raise HTTPException(status_code=202, detail="Report is still generating")
    return FileResponse(report.file_path, filename=f"recon-sentinel-report.{report.format.value}")


@router.delete("/{report_id}", status_code=204)
async def delete_report(report_id: UUID, db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    await db.delete(report)
    await db.commit()
