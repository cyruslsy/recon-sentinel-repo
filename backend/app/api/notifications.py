"""Notification Channel Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_project, authorize_notification_channel
from app.models.models import User, NotificationChannelModel, NotificationLog
from app.schemas.schemas import NotificationChannelCreate, NotificationChannelResponse, NotificationChannelUpdate

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{project_id}/channels", response_model=list[NotificationChannelResponse])
async def list_channels(project_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_project(project_id, user, db)
    result = await db.execute(
        select(NotificationChannelModel).where(NotificationChannelModel.project_id == project_id)
    )
    return result.scalars().all()


@router.post("/{project_id}/channels", response_model=NotificationChannelResponse, status_code=201)
async def create_channel(project_id: UUID, data: NotificationChannelCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    config = data.model_dump().get("config", {})

    # Encrypt SMTP password if present
    if isinstance(config, dict) and "password" in config and config["password"]:
        import hashlib, base64
        from cryptography.fernet import Fernet
        from app.core.config import get_settings
        s = get_settings()
        fernet_key = base64.urlsafe_b64encode(hashlib.sha256(s.JWT_SECRET_KEY.encode()).digest())
        config["password"] = Fernet(fernet_key).encrypt(config["password"].encode()).decode()
        config["_password_encrypted"] = True

    channel_data = data.model_dump()
    channel_data["config"] = config

    channel = NotificationChannelModel(
        **channel_data, project_id=project_id,
        created_by=user.id,
    )
    db.add(channel)
    await db.flush()
    await db.refresh(channel)
    return channel


@router.patch("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def update_channel(channel_id: UUID, data: NotificationChannelUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    channel = await authorize_notification_channel(channel_id, user, db)
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(channel, key, value)
    await db.flush()
    await db.refresh(channel)
    return channel


@router.delete("/channels/{channel_id}", status_code=204)
async def delete_channel(channel_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    channel = await authorize_notification_channel(channel_id, user, db)
    await db.delete(channel)
    await db.commit()


@router.post("/channels/{channel_id}/test")
async def test_notification(channel_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Send a test notification to verify channel configuration."""
    channel = await authorize_notification_channel(channel_id, user, db)
    from app.tasks.notifications import dispatch_notification
    dispatch_notification.delay(
        event_type="scan_complete",
        project_id=str(channel.project_id),
        payload={
            "target": "test.example.com",
            "total_findings": 42,
            "critical_count": 3,
            "value": "Test notification from Recon Sentinel",
            "detail": "If you see this, your notification channel is configured correctly.",
            "severity": "info",
        },
    )
    return {"status": "test_notification_queued", "channel_type": channel.channel_type.value}
