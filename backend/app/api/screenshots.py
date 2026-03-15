"""Screenshot API — List and serve screenshots captured by GoWitness."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.core.authorization import authorize_scan
from app.core.database import get_db
from app.models.models import Screenshot, User
from app.schemas.schemas import ScreenshotResponse

router = APIRouter()


@router.get("/", response_model=list[ScreenshotResponse])
async def list_screenshots(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all screenshots for a scan."""
    await authorize_scan(scan_id, user, db)
    result = await db.execute(
        select(Screenshot).where(Screenshot.scan_id == scan_id).order_by(Screenshot.created_at)
    )
    return result.scalars().all()


@router.get("/{screenshot_id}", response_model=ScreenshotResponse)
async def get_screenshot(
    screenshot_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get screenshot metadata."""
    screenshot = await db.get(Screenshot, screenshot_id)
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    await authorize_scan(screenshot.scan_id, user, db)
    return screenshot


@router.get("/{screenshot_id}/image")
async def get_screenshot_image(
    screenshot_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Serve the screenshot image file."""
    screenshot = await db.get(Screenshot, screenshot_id)
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    await authorize_scan(screenshot.scan_id, user, db)

    import os
    if not os.path.isfile(screenshot.file_path):
        raise HTTPException(status_code=404, detail="Screenshot file not found on disk")

    return FileResponse(screenshot.file_path, media_type="image/png")
