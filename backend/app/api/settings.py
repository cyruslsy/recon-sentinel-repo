"""Settings Routes — API Keys, Scan Engines, System Config"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import ApiKey, ScanEngine, LlmUsageLog
from app.schemas.schemas import ApiKeyCreate, ApiKeyResponse, ScanEngineCreate, ScanEngineResponse

router = APIRouter()


# ─── API Keys ─────────────────────────────────────────────────────────

@router.get("/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(project_id: UUID | None = None, db: AsyncSession = Depends(get_db)):
    q = select(ApiKey).order_by(ApiKey.service_name)
    if project_id:
        q = q.where(ApiKey.project_id == project_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/api-keys", response_model=ApiKeyResponse, status_code=201)
async def add_api_key(data: ApiKeyCreate, project_id: UUID | None = None, db: AsyncSession = Depends(get_db)):
    key = ApiKey(
        service_name=data.service_name,
        api_key_encrypted=data.api_key,  # TODO: Encrypt with pgcrypto
        project_id=project_id,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key


@router.delete("/api-keys/{key_id}", status_code=204)
async def delete_api_key(key_id: UUID, db: AsyncSession = Depends(get_db)):
    key = await db.get(ApiKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    await db.delete(key)
    await db.commit()


@router.post("/api-keys/{key_id}/verify")
async def verify_api_key(key_id: UUID, db: AsyncSession = Depends(get_db)):
    """Test if an API key is still valid by making a lightweight request to the service."""
    key = await db.get(ApiKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    # TODO: Call service health check endpoint
    return {"status": "verification_queued", "service": key.service_name}


# ─── Scan Engines ─────────────────────────────────────────────────────

@router.get("/engines", response_model=list[ScanEngineResponse])
async def list_engines(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanEngine).order_by(ScanEngine.is_default.desc(), ScanEngine.name))
    return result.scalars().all()


@router.post("/engines", response_model=ScanEngineResponse, status_code=201)
async def create_engine(data: ScanEngineCreate, db: AsyncSession = Depends(get_db)):
    engine = ScanEngine(
        **data.model_dump(),
        created_by="00000000-0000-0000-0000-000000000000",
    )
    # TODO: Parse YAML to JSON and validate structure
    db.add(engine)
    await db.commit()
    await db.refresh(engine)
    return engine


@router.get("/engines/{engine_id}", response_model=ScanEngineResponse)
async def get_engine(engine_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = await db.get(ScanEngine, engine_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Scan engine not found")
    return engine


@router.put("/engines/{engine_id}", response_model=ScanEngineResponse)
async def update_engine(engine_id: UUID, data: ScanEngineCreate, db: AsyncSession = Depends(get_db)):
    engine = await db.get(ScanEngine, engine_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Scan engine not found")
    for key, value in data.model_dump().items():
        setattr(engine, key, value)
    await db.commit()
    await db.refresh(engine)
    return engine


@router.delete("/engines/{engine_id}", status_code=204)
async def delete_engine(engine_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = await db.get(ScanEngine, engine_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Scan engine not found")
    await db.delete(engine)
    await db.commit()


# ─── LLM Usage & Cost ────────────────────────────────────────────────

@router.get("/llm-usage")
async def llm_usage_summary(scan_id: UUID | None = None, db: AsyncSession = Depends(get_db)):
    """Get LLM usage and cost summary."""
    from sqlalchemy import func
    
    q = select(
        LlmUsageLog.model_name,
        LlmUsageLog.task_type,
        func.sum(LlmUsageLog.tokens_input).label("total_input"),
        func.sum(LlmUsageLog.tokens_output).label("total_output"),
        func.sum(LlmUsageLog.cost_usd).label("total_cost"),
        func.count().label("call_count"),
    ).group_by(LlmUsageLog.model_name, LlmUsageLog.task_type)
    
    if scan_id:
        q = q.where(LlmUsageLog.scan_id == scan_id)
    
    result = await db.execute(q)
    return [
        {
            "model": r.model_name, "task": r.task_type,
            "tokens_in": r.total_input, "tokens_out": r.total_output,
            "cost_usd": float(r.total_cost), "calls": r.call_count,
        }
        for r in result.all()
    ]
