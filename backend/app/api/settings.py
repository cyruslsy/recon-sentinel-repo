"""Settings Routes — API Keys, Scan Engines, System Config"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, ApiKey, ScanEngine, LlmUsageLog
from app.schemas.schemas import ApiKeyCreate, ApiKeyResponse, ScanEngineCreate, ScanEngineResponse

import logging
logger = logging.getLogger(__name__)

router = APIRouter()


# ─── API Keys ─────────────────────────────────────────────────────────

@router.get("/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(project_id: UUID | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    q = select(ApiKey).where(ApiKey.created_by == user.id).order_by(ApiKey.service_name)
    if project_id:
        q = q.where(ApiKey.project_id == project_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/api-keys", response_model=ApiKeyResponse, status_code=201)
async def add_api_key(data: ApiKeyCreate, project_id: UUID | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Encrypt API key before storage
    import hashlib
    import base64
    from app.core.config import get_settings
    s = get_settings()
    fernet_key = base64.urlsafe_b64encode(hashlib.sha256(s.JWT_SECRET_KEY.encode()).digest())
    from cryptography.fernet import Fernet
    encrypted = Fernet(fernet_key).encrypt(data.api_key.encode()).decode()

    key = ApiKey(
        service_name=data.service_name,
        api_key_encrypted=encrypted,
        project_id=project_id,
        created_by=user.id,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key


@router.delete("/api-keys/{key_id}", status_code=204)
async def delete_api_key(key_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    key = await db.get(ApiKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    if key.created_by != user.id and not (user.role and user.role.value == "admin"):
        raise HTTPException(status_code=403, detail="Access denied")
    await db.delete(key)
    await db.commit()


@router.post("/api-keys/{key_id}/verify")
async def verify_api_key(key_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Test if an API key is still valid by making a lightweight request to the service."""
    key = await db.get(ApiKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    if key.created_by != user.id and not (user.role and user.role.value == "admin"):
        raise HTTPException(status_code=403, detail="Access denied")

    # Decrypt and test the key against its service
    import hashlib, base64
    from app.core.config import get_settings
    from cryptography.fernet import Fernet
    import httpx

    s = get_settings()
    fernet_key = base64.urlsafe_b64encode(hashlib.sha256(s.JWT_SECRET_KEY.encode()).digest())
    try:
        decrypted = Fernet(fernet_key).decrypt(key.api_key_encrypted.encode()).decode()
    except Exception:
        return {"status": "error", "service": key.service_name, "detail": "Decryption failed — key may be corrupted"}

    # Service-specific health checks
    health_endpoints = {
        "shodan": ("https://api.shodan.io/api-info?key={key}", "query_credits"),
        "virustotal": ("https://www.virustotal.com/api/v3/users/me", None),
        "hibp": ("https://haveibeenpwned.com/api/v3/subscription/status", None),
    }

    service = key.service_name.lower()
    if service not in health_endpoints:
        return {"status": "unknown", "service": key.service_name, "detail": "No health check available for this service"}

    url_template, check_field = health_endpoints[service]
    url = url_template.replace("{key}", decrypted)
    headers = {}
    if service == "virustotal":
        headers["x-apikey"] = decrypted
        url = health_endpoints[service][0]
    elif service == "hibp":
        headers["hibp-api-key"] = decrypted

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return {"status": "valid", "service": key.service_name}
            else:
                return {"status": "invalid", "service": key.service_name, "detail": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "service": key.service_name, "detail": str(e)}


# ─── Scan Engines ─────────────────────────────────────────────────────

@router.get("/engines", response_model=list[ScanEngineResponse])
async def list_engines(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanEngine).order_by(ScanEngine.is_default.desc(), ScanEngine.name))
    return result.scalars().all()


@router.post("/engines", response_model=ScanEngineResponse, status_code=201)
async def create_engine(data: ScanEngineCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    engine = ScanEngine(
        **data.model_dump(),
        created_by=user.id,
    )
    # Validate engine config if it looks like YAML/JSON
    if hasattr(data, "config") and data.config:
        import json as _json
        try:
            if isinstance(data.config, str):
                # Try JSON first, then YAML
                try:
                    parsed = _json.loads(data.config)
                except _json.JSONDecodeError:
                    import yaml
                    parsed = yaml.safe_load(data.config)
                engine.config = parsed
            # Validate required fields
            if isinstance(engine.config, dict):
                valid_keys = {"agents", "phases", "max_targets", "timeout", "profile", "notifications"}
                unknown = set(engine.config.keys()) - valid_keys
                if unknown:
                    logger.warning(f"Engine config has unknown keys: {unknown}")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid engine config: {e}")
    db.add(engine)
    await db.commit()
    await db.refresh(engine)
    return engine


@router.get("/engines/{engine_id}", response_model=ScanEngineResponse)
async def get_engine(engine_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    engine = await db.get(ScanEngine, engine_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Scan engine not found")
    if engine.created_by != user.id and not (user.role and user.role.value == "admin"):
        raise HTTPException(status_code=403, detail="Access denied")
    return engine


@router.put("/engines/{engine_id}", response_model=ScanEngineResponse)
async def update_engine(engine_id: UUID, data: ScanEngineCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    engine = await db.get(ScanEngine, engine_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Scan engine not found")
    if engine.created_by != user.id and not (user.role and user.role.value == "admin"):
        raise HTTPException(status_code=403, detail="Access denied")
    for key, value in data.model_dump().items():
        setattr(engine, key, value)
    await db.commit()
    await db.refresh(engine)
    return engine


@router.delete("/engines/{engine_id}", status_code=204)
async def delete_engine(engine_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    engine = await db.get(ScanEngine, engine_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Scan engine not found")
    if engine.created_by != user.id and not (user.role and user.role.value == "admin"):
        raise HTTPException(status_code=403, detail="Access denied")
    await db.delete(engine)
    await db.commit()


# ─── LLM Usage & Cost ────────────────────────────────────────────────

@router.get("/llm-usage")
async def llm_usage_summary(scan_id: UUID | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
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
