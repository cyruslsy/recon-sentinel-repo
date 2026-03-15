"""Agent Runs & Health Events Routes"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.tz import utc_now
from app.core.auth import get_current_user
from app.core.authorization import authorize_scan, authorize_agent_run, authorize_health_event
from app.core.celery_app import celery_app
from app.models.models import User, AgentRun, HealthEvent
from app.models.enums import AgentStatus
from app.schemas.schemas import AgentRunResponse, AgentRunBrief, HealthEventResponse, HealthEventDecision

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Agent Runs ───────────────────────────────────────────────────────

@router.get("/", response_model=list[AgentRunResponse])
async def list_agent_runs(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await authorize_scan(scan_id, user, db)
    result = await db.execute(
        select(AgentRun).where(AgentRun.scan_id == scan_id).order_by(AgentRun.phase, AgentRun.created_at)
    )
    return result.scalars().all()


@router.get("/{agent_run_id}", response_model=AgentRunResponse)
async def get_agent_run(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await authorize_agent_run(agent_run_id, user, db)


@router.post("/{agent_run_id}/pause")
async def pause_agent(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Pause a running agent. Sends SIGUSR1 to the Celery task."""
    agent = await authorize_agent_run(agent_run_id, user, db)
    agent.status = AgentStatus.PAUSED
    await db.commit()
    return {"status": "agent_paused"}


@router.post("/{agent_run_id}/resume")
async def resume_agent(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Resume a paused agent by re-dispatching its Celery task."""
    agent = await authorize_agent_run(agent_run_id, user, db)
    if agent.status != "paused":
        raise HTTPException(status_code=400, detail="Agent is not paused")

    agent.status = AgentStatus.RUNNING
    await db.commit()

    # Re-dispatch the agent task via Celery
    task_name = f"app.agents.{agent.agent_type}.run_{agent.agent_type}_agent"
    celery_app.send_task(task_name, args=[
        str(agent.scan_id), agent.target_host or "", str(agent.scan_id), {}
    ])
    logger.info(f"Agent {agent_run_id} resumed, task {task_name} dispatched")
    return {"status": "agent_resumed", "task_name": task_name}


@router.post("/{agent_run_id}/rerun")
async def rerun_agent(agent_run_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Re-run a completed/failed agent from scratch. Creates new AgentRun."""
    original = await authorize_agent_run(agent_run_id, user, db)
    if original.status not in ("completed", "error", "cancelled"):
        raise HTTPException(status_code=400, detail="Can only rerun completed/failed/cancelled agents")

    # Create new AgentRun with same config
    new_run = AgentRun(
        scan_id=original.scan_id,
        agent_type=original.agent_type,
        agent_name=original.agent_name,
        phase=original.phase,
        target_host=original.target_host,
        status=AgentStatus.PENDING,
    )
    db.add(new_run)
    await db.flush()
    await db.refresh(new_run)

    # Dispatch to Celery
    task_name = f"app.agents.{original.agent_type}.run_{original.agent_type}_agent"
    celery_app.send_task(task_name, args=[
        str(original.scan_id), original.target_host or "", str(original.scan_id), {}
    ])
    logger.info(f"Agent {agent_run_id} rerun as {new_run.id}")
    return {"status": "agent_rerun_queued", "new_agent_run_id": str(new_run.id)}


# ─── Health Events ────────────────────────────────────────────────────

@router.get("/health", response_model=list[HealthEventResponse])
async def list_health_events(
    scan_id: UUID,
    event_type: str | None = None,
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List health events for a scan (Agent Health Feed)."""
    await authorize_scan(scan_id, user, db)
    q = select(HealthEvent).where(HealthEvent.scan_id == scan_id).order_by(HealthEvent.created_at.desc()).limit(limit)
    if event_type:
        q = q.where(HealthEvent.event_type == event_type)
    result = await db.execute(q)
    events = result.scalars().all()

    # Resolve agent_type/agent_name from AgentRun (single batch query)
    agent_run_ids = list({e.agent_run_id for e in events if e.agent_run_id})
    if agent_run_ids:
        ar_result = await db.execute(
            select(AgentRun.id, AgentRun.agent_type, AgentRun.agent_name)
            .where(AgentRun.id.in_(agent_run_ids))
        )
        agent_map = {row.id: (row.agent_type, row.agent_name) for row in ar_result.all()}
    else:
        agent_map = {}

    # Build response dicts with agent info injected
    results = []
    for event in events:
        d = {c.name: getattr(event, c.name) for c in event.__table__.columns}
        agent_info = agent_map.get(event.agent_run_id, (None, None))
        d["agent_type"] = agent_info[0]
        d["agent_name"] = agent_info[1]
        results.append(d)
    return results


@router.get("/health/{event_id}", response_model=HealthEventResponse)
async def get_health_event(event_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await authorize_health_event(event_id, user, db)


@router.post("/health/{event_id}/decide", response_model=HealthEventResponse)
async def decide_health_escalation(event_id: UUID, data: HealthEventDecision, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Respond to an escalate_user health event with a decision."""
    event = await authorize_health_event(event_id, user, db)
    if event.event_type != "escalate_user":
        raise HTTPException(status_code=400, detail="Only escalate_user events can be decided")
    if event.user_decision:
        raise HTTPException(status_code=400, detail="Already decided")

    event.user_decision = data.decision
    event.decided_at = utc_now()
    await db.flush()
    await db.refresh(event)

    # Publish decision to Redis so the waiting agent can pick it up
    try:
        from app.core.redis import get_redis
        r = await get_redis()
        await r.publish(
            f"health_decision:{event.id}",
            data.decision,
        )
        logger.info(f"Health decision '{data.decision}' published for event {event_id}")
    except Exception as e:
        logger.warning(f"Failed to publish health decision: {e}")

    return event
