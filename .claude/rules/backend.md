---
paths:
  - "backend/**"
---
# Backend Rules

## SQLAlchemy 2.0

ORM objects are immutable for extra attributes:
```python
# NEVER: scan.target_value = "example.com"
# ALWAYS: d = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
```

## Async Patterns

- All DB operations use `AsyncSessionLocal` context manager
- All external tool calls use `asyncio.create_subprocess_exec` (NEVER `subprocess.run`)
- Process groups: start tools with `start_new_session=True`, kill via `os.killpg`

## API Conventions

- Routes in `backend/app/api/`, one file per resource
- Every endpoint uses `authorize_*` helper
- Response schemas in `schemas.py` — use `FindingResponse` (full) vs `FindingBrief` (list)
- Errors: raise `HTTPException` with appropriate status codes (400, 401, 403, 404, 409)

## LLM Calls

- Use `llm_call()` from `core/llm.py` with semantic tiers: `routing`, `analysis`, `reasoning`
- Never use model names directly — tiers are resolved via `LLM_PRESET`
- JSON responses: pass `response_format="json"` and parse with `parse_llm_json()`

## Test Conventions

- pytest + httpx.AsyncClient, fixtures in `conftest.py`
- `@pytest.mark.asyncio` on all async tests
- Test happy path + error cases (401, 403, 404, 409)
