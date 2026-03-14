"""Credential Leak Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan, authorize_credential
from app.models.models import User, CredentialLeak
from app.schemas.schemas import CredentialLeakResponse, CredentialLeakSummary

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=list[CredentialLeakResponse])
async def list_credentials(
    scan_id: UUID,
    has_password: bool | None = None,
    has_plaintext: bool | None = None,
    limit: int = Query(50, le=500),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await authorize_scan(scan_id, user, db)
    q = select(CredentialLeak).where(CredentialLeak.scan_id == scan_id)
    if has_password is not None:
        q = q.where(CredentialLeak.has_password == has_password)
    if has_plaintext is not None:
        q = q.where(CredentialLeak.has_plaintext == has_plaintext)
    q = q.order_by(CredentialLeak.breach_count.desc()).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/summary", response_model=CredentialLeakSummary)
async def credential_summary(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_scan(scan_id, user, db)
    base = select(func.count()).select_from(CredentialLeak).where(CredentialLeak.scan_id == scan_id)
    total = (await db.execute(base)).scalar() or 0
    with_pw = (await db.execute(base.where(CredentialLeak.has_password == True))).scalar() or 0  # noqa
    with_pt = (await db.execute(base.where(CredentialLeak.has_plaintext == True))).scalar() or 0  # noqa
    reuse = (await db.execute(base.where(CredentialLeak.password_reuse_detected == True))).scalar() or 0  # noqa
    return CredentialLeakSummary(total_emails=total, with_passwords=with_pw, with_plaintext=with_pt, password_reuse_count=reuse)


@router.get("/{cred_id}", response_model=CredentialLeakResponse)
async def get_credential(cred_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    cred = await authorize_credential(cred_id, user, db)
    # Log sensitive data access to audit trail
    from app.models.models import AuditLog
    audit = AuditLog(
        user_id=user.id,
        action="credential_view",
        resource_type="credential_leak",
        resource_id=cred_id,
        metadata_={"detail": f"User {user.email} viewed credential {cred_id}"},
    )
    db.add(audit)
    await db.commit()
    return cred
