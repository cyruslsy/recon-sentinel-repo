"""Notification Channel Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, NotificationChannelModel, NotificationLog
from app.schemas.schemas import NotificationChannelCreate, NotificationChannelResponse, NotificationChannelUpdate

router = APIRouter()


@router.get("/{project_id}/channels", response_model=list[NotificationChannelResponse])
async def list_channels(project_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(NotificationChannelModel).where(NotificationChannelModel.project_id == project_id)
    )
    return result.scalars().all()


@router.post("/{project_id}/channels", response_model=NotificationChannelResponse, status_code=201)
async def create_channel(project_id: UUID, data: NotificationChannelCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    channel = NotificationChannelModel(
        **data.model_dump(), project_id=project_id,
        created_by=user.id,
    )
    db.add(channel)
    await db.commit()
    await db.refresh(channel)
    return channel


@router.patch("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def update_channel(channel_id: UUID, data: NotificationChannelUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    channel = await db.get(NotificationChannelModel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(channel, key, value)
    await db.commit()
    await db.refresh(channel)
    return channel


@router.delete("/channels/{channel_id}", status_code=204)
async def delete_channel(channel_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    channel = await db.get(NotificationChannelModel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    await db.delete(channel)
    await db.commit()


@router.post("/channels/{channel_id}/test")
async def test_notification(channel_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Send a test notification to verify channel configuration."""
    channel = await db.get(NotificationChannelModel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    # TODO: Celery — notification_sender.send_test.delay(str(channel_id))
    return {"status": "test_notification_queued", "channel_type": channel.channel_type.value}
