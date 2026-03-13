"""
Recon Sentinel — LLM Integration Layer
Wraps LiteLLM for model routing, fallback, cost tracking, and budget enforcement.

Amendments:
  #7  — LLM fallback policy (LiteLLM chain)
  #25 — Fallback task allowlist (local models blocked from critical tasks)
  #26 — Monthly budget cap with auto-pause
"""

import json
import logging
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.tz import utc_now
from app.core.database import AsyncSessionLocal
from app.core.tz import utc_now
from app.models.models import LlmUsageLog
from app.core.tz import utc_now

try:
    import litellm
except ImportError:
    litellm = None  # type: ignore — graceful degradation if not installed

logger = logging.getLogger(__name__)

settings = get_settings()

# ─── Model Tiers ──────────────────────────────────────────────

MODELS = {
    "routing": "claude-haiku-4.5-20251001",    # Fast, cheap — planning/routing
    "analysis": "claude-sonnet-4-6-20250514",   # Smart — gate analysis, reports
    "reasoning": "claude-opus-4-6-20250410",    # Deep — complex reasoning (rare)
    "local": "ollama/qwen2.5:7b",              # Free — fallback
}

# Cost per million tokens (input/output)
COST_RATES = {
    "claude-haiku-4.5-20251001":  {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6-20250514": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6-20250410":   {"input": 5.0, "output": 25.0},
    "ollama/qwen2.5:7b":          {"input": 0.0, "output": 0.0},
}

# Amendment #25: Tasks that MUST NOT fall back to local models
FALLBACK_BLOCKED_TASKS = frozenset({
    "replan",           # Wrong decision = wasted scan time
    "mitre_classify",   # Misclassification corrupts heatmap
    "scope_check",      # Wrong scope = legal liability
    "gate_analysis",    # Under-scoped approval = missed vulns
})

FALLBACK_ALLOWED_TASKS = frozenset({
    "summarize", "format", "chat", "report", "general",
})


# ─── Main LLM Call ────────────────────────────────────────────

async def llm_call(
    messages: list[dict],
    model_tier: str = "routing",
    task_type: str = "general",
    scan_id: str | None = None,
    max_tokens: int = 1000,
    temperature: float = 0.1,
    response_format: str | None = None,
) -> dict:
    """
    Make an LLM call with automatic fallback, cost tracking, and budget enforcement.
    
    Args:
        messages: Chat messages [{"role": "user", "content": "..."}]
        model_tier: "routing" (Haiku), "analysis" (Sonnet), "reasoning" (Opus), "local"
        task_type: Used for fallback allowlist and audit
        scan_id: Optional scan ID for cost attribution
        max_tokens: Max response tokens
        temperature: Sampling temperature
        response_format: "json" to request JSON output
    
    Returns:
        {"content": str, "model": str, "tokens_in": int, "tokens_out": int, "cost_usd": Decimal}
    """
    model = MODELS.get(model_tier, MODELS["routing"])

    if litellm is None:
        raise LLMUnavailableError("litellm is not installed")

    # Amendment #26: Budget check before call
    await _check_budget()

    # Build kwargs — copy messages to avoid mutating caller's list
    kwargs = {
        "model": model,
        "messages": [dict(m) for m in messages],  # shallow copy each message
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    if settings.ANTHROPIC_API_KEY:
        litellm.anthropic_key = settings.ANTHROPIC_API_KEY

    if response_format == "json":
        # Append instruction for JSON output (on our copy, not caller's original)
        if kwargs["messages"] and kwargs["messages"][-1]["role"] == "user":
            kwargs["messages"][-1]["content"] += "\n\nRespond with valid JSON only. No markdown, no preamble."

    # Attempt primary model
    try:
        response = await litellm.acompletion(**kwargs)
        return await _process_response(response, model, task_type, scan_id)

    except Exception as primary_error:
        logger.warning(f"Primary model {model} failed: {primary_error}")

        # Amendment #25: Check if fallback is allowed for this task type
        if task_type in FALLBACK_BLOCKED_TASKS:
            raise LLMUnavailableError(
                f"Primary model failed and fallback is blocked for task '{task_type}'. "
                f"This task requires Claude, not a local model. Error: {primary_error}"
            )

        # Try fallback to local model
        if model_tier != "local":
            logger.info(f"Falling back to local model for task '{task_type}'")
            kwargs["model"] = MODELS["local"]
            try:
                response = await litellm.acompletion(**kwargs)
                result = await _process_response(
                    response, MODELS["local"], task_type, scan_id, is_fallback=True
                )
                result["fallback"] = True
                return result
            except Exception as fallback_error:
                logger.error(f"Fallback model also failed: {fallback_error}")
                raise LLMUnavailableError(
                    f"Both primary ({model}) and fallback ({MODELS['local']}) failed. "
                    f"Primary: {primary_error}. Fallback: {fallback_error}"
                )

        raise LLMUnavailableError(f"LLM call failed: {primary_error}")


# ─── Response Processing + Cost Tracking ──────────────────────

async def _process_response(
    response,
    model: str,
    task_type: str,
    scan_id: str | None,
    is_fallback: bool = False,
) -> dict:
    """Extract content, calculate cost, log usage."""
    content = response.choices[0].message.content or ""
    usage = response.usage

    tokens_in = usage.prompt_tokens if usage else 0
    tokens_out = usage.completion_tokens if usage else 0

    # Calculate cost
    rates = COST_RATES.get(model, {"input": 0, "output": 0})
    cost_usd = Decimal(str(
        (tokens_in * rates["input"] / 1_000_000)
        + (tokens_out * rates["output"] / 1_000_000)
    ))

    # Log to database
    try:
        async with AsyncSessionLocal() as db:
            log = LlmUsageLog(
                scan_id=uuid.UUID(scan_id) if scan_id else None,
                task_type=task_type,
                model_name=model,
                tokens_input=tokens_in,
                tokens_output=tokens_out,
                cost_usd=cost_usd,
                cached_tokens=0,
                latency_ms=int(getattr(response, "_response_ms", 0)),
            )
            db.add(log)
            await db.commit()
    except Exception as e:
        logger.warning(f"Failed to log LLM usage: {e}")

    return {
        "content": content,
        "model": model,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "cost_usd": cost_usd,
        "is_fallback": is_fallback,
    }


# ─── Budget Enforcement (Amendment #26) ───────────────────────

async def _check_budget() -> None:
    """Check monthly LLM spend against configured budget cap."""
    budget = Decimal(str(settings.LLM_MONTHLY_BUDGET_USD))
    if budget <= 0:
        return  # Budget enforcement disabled

    month_start = utc_now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(func.sum(LlmUsageLog.cost_usd)).where(
                    LlmUsageLog.created_at >= month_start
                )
            )
            current_spend = result.scalar() or Decimal("0")

        if current_spend >= budget:
            raise BudgetExceededError(
                f"Monthly LLM budget exhausted: ${current_spend:.2f} / ${budget:.2f}"
            )

        if current_spend / budget > Decimal("0.8"):
            logger.warning(f"LLM budget at {current_spend/budget*100:.0f}%: ${current_spend:.2f} / ${budget:.2f}")

    except BudgetExceededError:
        raise
    except Exception as e:
        logger.warning(f"Budget check failed (allowing call): {e}")


# ─── Helper: JSON Parsing ─────────────────────────────────────

def parse_llm_json(content: str) -> dict | list:
    """Parse JSON from LLM response, stripping markdown fences if present."""
    clean = content.strip()
    if clean.startswith("```"):
        # Strip ```json ... ```
        lines = clean.split("\n")
        clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return json.loads(clean)


# ─── Exceptions ───────────────────────────────────────────────

class LLMUnavailableError(Exception):
    """Raised when no LLM backend is available for a critical task."""
    pass


class BudgetExceededError(Exception):
    """Raised when monthly LLM budget is exhausted."""
    pass
