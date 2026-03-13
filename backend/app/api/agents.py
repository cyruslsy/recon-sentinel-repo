"""Agent Runs & Health Events Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.tz import utc_now
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan
from app.core.tz import utc_now
from app.models.models import User, AgentRun, HealthEvent
from app.core.tz import utc_now
from app.schemas.schemas import AgentRunResponse, AgentRunBrief, HealthEventResponse, HealthEventDecision
from app.core.tz import utc_now

router = APIRouter()


# ─── Agent Runs ───────────────────────────────────────────────────────

@router.get("/", response_model=list[AgentRunBrief])
async def list_agent_runs(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_scan(scan_id, user, db)
    result = await db.execute(
        select(AgentRun).where(AgentRun.scan_id == scan_id).order_by(AgentRun.phase, AgentRun.created_at)
    )
    return result.scalars().all()


@router.get("/{agent_run_id}", response_model=AgentRunResponse)
async def get_agent_run(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    agent = await db.get(AgentRun, agent_run_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent run not found")
    return agent


@router.post("/{agent_run_id}/pause")
async def pause_agent(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Pause a running agent."""
    agent = await db.get(AgentRun, agent_run_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent run not found")
    agent.status = "paused"
    await db.commit()
    return {"status": "agent_paused"}


@router.post("/{agent_run_id}/resume")
async def resume_agent(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Resume a paused agent."""
    agent = await db.get(AgentRun, agent_run_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent run not found")
    agent.status = "running"
    await db.commit()
    # TODO: Celery restart agent task
    return {"status": "agent_resumed"}


@router.post("/{agent_run_id}/rerun")
async def rerun_agent(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Re-run a completed/failed agent from scratch."""
    agent = await db.get(AgentRun, agent_run_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent run not found")
    # TODO: Create new AgentRun with same config, dispatch to Celery
    return {"status": "agent_rerun_queued", "new_agent_run_id": "placeholder"}


# ─── Health Events ────────────────────────────────────────────────────

@router.get("/health", response_model=list[HealthEventResponse])
async def list_health_events(
    scan_id: UUID,
    event_type: str | None = None,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List health events for a scan (Agent Health Feed)."""
    q = select(HealthEvent).where(HealthEvent.scan_id == scan_id).order_by(HealthEvent.created_at.desc()).limit(limit)
    if event_type:
        q = q.where(HealthEvent.event_type == event_type)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/health/{event_id}", response_model=HealthEventResponse)
async def get_health_event(event_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    event = await db.get(HealthEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Health event not found")
    return event


@router.post("/health/{event_id}/decide", response_model=HealthEventResponse)
async def decide_health_escalation(event_id: UUID, data: HealthEventDecision, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Respond to an escalate_user health event with a decision."""
    event = await db.get(HealthEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Health event not found")
    if event.event_type != "escalate_user":
        raise HTTPException(status_code=400, detail="Only escalate_user events can be decided")
    if event.user_decision:
        raise HTTPException(status_code=400, detail="Already decided")
    
    event.user_decision = data.decision
    from datetime import datetime
    event.decided_at = utc_now()
    await db.commit()
    await db.refresh(event)
    
    # TODO: Signal agent to proceed with the user's decision
    return event
