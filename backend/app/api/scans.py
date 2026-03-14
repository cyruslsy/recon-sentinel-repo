"""Scan Routes — Launch, monitor, approve, and manage scan lifecycle"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.tz import utc_now
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan, authorize_target
from app.models.models import User, Scan, ApprovalGate, Target
from app.models.enums import ScanStatus, ApprovalDecision
from app.schemas.schemas import (
    ScanCreate, ScanResponse, ScanBrief,
    ApprovalGateResponse, ApprovalGateDecision,
)

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=list[ScanResponse])
async def list_scans(
    target_id: UUID | None = None,
    status: ScanStatus | None = None,
    include_archived: bool = False,
    limit: int = Query(20, le=100),
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List scans visible to the current user."""
    q = select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    if user.role and user.role.value == "admin":
        pass  # Admin sees all scans
    else:
        # Scans the user created OR scans on targets in projects the user is a member of
        from app.models.models import ProjectMember
        accessible_via_project = (
            select(Scan.id)
            .join(Target, Scan.target_id == Target.id)
            .join(ProjectMember, ProjectMember.project_id == Target.project_id)
            .where(ProjectMember.user_id == user.id)
        )
        q = q.where((Scan.created_by == user.id) | (Scan.id.in_(accessible_via_project)))
    if target_id:
        q = q.where(Scan.target_id == target_id)
    if status:
        q = q.where(Scan.status == status)
    if not include_archived:
        q = q.where(Scan.is_archived == False)  # noqa: E712
    result = await db.execute(q)
    scans = result.scalars().all()

    # Resolve target_value for each scan (single query for all target_ids)
    target_ids = list({s.target_id for s in scans})
    if target_ids:
        tgt_result = await db.execute(
            select(Target.id, Target.target_value).where(Target.id.in_(target_ids))
        )
        target_map = {row.id: row.target_value for row in tgt_result.all()}
    else:
        target_map = {}

    # Build response dicts with target_value injected
    results = []
    for scan in scans:
        d = {c.name: getattr(scan, c.name) for c in scan.__table__.columns}
        d["target_value"] = target_map.get(scan.target_id)
        results.append(d)
    return results


@router.post("/", response_model=ScanResponse, status_code=201)
async def launch_scan(data: ScanCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Launch a new scan. The orchestrator begins the passive phase immediately."""
    # Verify user has access to this target's project
    target = await authorize_target(data.target_id, user, db)

    scan = Scan(
        **data.model_dump(),
        status=ScanStatus.RUNNING,
        created_by=user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Dispatch to Celery orchestrator
    from app.tasks.orchestrator import start_scan
    start_scan.delay(str(scan.id), target.target_value, str(target.project_id), scan.profile.value)
    logger.info(f"Scan {scan.id} launched by user {user.id}")

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = await authorize_scan(scan_id, user, db)
    # Resolve target_value — build dict to avoid mutating ORM object
    tgt = await db.execute(select(Target.target_value).where(Target.id == scan.target_id))
    d = {c.name: getattr(scan, c.name) for c in scan.__table__.columns}
    d["target_value"] = tgt.scalar_one_or_none()
    return d


@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Stop a running scan. All active agents are cancelled."""
    scan = await authorize_scan(scan_id, user, db)
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Scan is not running")
    scan.status = ScanStatus.CANCELLED
    await db.commit()
    logger.info(f"Scan {scan_id} stopped by user {user.id}")

    # Revoke all running agent tasks for this scan
    from sqlalchemy import select as sel
    from app.models.models import AgentRun
    from app.core.celery_app import celery_app as _celery
    result = await db.execute(
        sel(AgentRun.celery_task_id).where(
            AgentRun.scan_id == scan_id,
            AgentRun.status.in_(["running", "queued"]),
        )
    )
    task_ids = [r[0] for r in result.all() if r[0]]
    for tid in task_ids:
        _celery.control.revoke(tid, terminate=True, signal="SIGTERM")
    logger.info(f"Revoked {len(task_ids)} agent tasks for scan {scan_id}")

    return {"status": "scan_stopped", "scan_id": str(scan_id), "revoked_tasks": len(task_ids)}


@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Pause scan at current phase. Can be resumed later."""
    scan = await authorize_scan(scan_id, user, db)
    scan.status = ScanStatus.PAUSED
    await db.commit()
    return {"status": "scan_paused", "scan_id": str(scan_id)}


@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Resume a paused or errored scan from its LangGraph checkpoint."""
    scan = await authorize_scan(scan_id, user, db)
    if scan.status not in (ScanStatus.PAUSED, ScanStatus.FAILED):
        raise HTTPException(status_code=400, detail=f"Cannot resume scan with status '{scan.status.value}'")

    if not scan.langgraph_checkpoint:
        raise HTTPException(status_code=400, detail="No checkpoint found — scan cannot be resumed")

    # Atomic status transition: use UPDATE ... WHERE to prevent double resume race
    from sqlalchemy import update
    result = await db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.in_([ScanStatus.PAUSED, ScanStatus.FAILED]))
        .values(status=ScanStatus.RUNNING, error_message=None)
    )
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=409, detail="Scan already resumed by another request")

    from app.tasks.orchestrator import resume_scan_from_checkpoint
    resume_scan_from_checkpoint.delay(str(scan_id))

    return {"status": "scan_resumed", "scan_id": str(scan_id), "phase": scan.phase.value if scan.phase else "unknown"}


@router.post("/{scan_id}/archive")
async def archive_scan(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = await authorize_scan(scan_id, user, db)
    scan.is_archived = True
    await db.commit()
    return {"status": "archived"}


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = await authorize_scan(scan_id, user, db)
    await db.delete(scan)
    await db.commit()


# ─── Approval Gates ──────────────────────────────────────────────────

@router.get("/{scan_id}/gates", response_model=list[ApprovalGateResponse])
async def list_gates(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_scan(scan_id, user, db)
    result = await db.execute(
        select(ApprovalGate).where(ApprovalGate.scan_id == scan_id).order_by(ApprovalGate.gate_number)
    )
    return result.scalars().all()


@router.get("/{scan_id}/gates/{gate_number}", response_model=ApprovalGateResponse)
async def get_gate(scan_id: UUID, gate_number: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_scan(scan_id, user, db)
    result = await db.execute(
        select(ApprovalGate).where(ApprovalGate.scan_id == scan_id, ApprovalGate.gate_number == gate_number)
    )
    gate = result.scalar_one_or_none()
    if not gate:
        raise HTTPException(status_code=404, detail="Approval gate not found")
    return gate


@router.post("/{scan_id}/gates/{gate_number}/decide", response_model=ApprovalGateResponse)
async def decide_gate(
    scan_id: UUID, gate_number: int, data: ApprovalGateDecision, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Submit human decision at an approval gate. Resumes the scan pipeline."""
    await authorize_scan(scan_id, user, db)
    result = await db.execute(
        select(ApprovalGate).where(ApprovalGate.scan_id == scan_id, ApprovalGate.gate_number == gate_number)
    )
    gate = result.scalar_one_or_none()
    if not gate:
        raise HTTPException(status_code=404, detail="Approval gate not found")
    if gate.decision != ApprovalDecision.PENDING:
        raise HTTPException(status_code=400, detail="Gate already decided")

    gate.decision = data.decision
    gate.user_modifications = data.user_modifications
    from datetime import datetime
    gate.decided_at = utc_now()
    await db.commit()
    await db.refresh(gate)

    # Signal orchestrator to resume from checkpoint
    from app.tasks.orchestrator import handle_gate_decision
    handle_gate_decision.delay(
        str(scan_id), gate_number, data.decision.value, data.user_modifications
    )
    return gate
