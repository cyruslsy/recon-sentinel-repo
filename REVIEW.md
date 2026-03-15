# Recon Sentinel — Code Review Rules

## Critical (must block PR)

- Any new API endpoint missing `authorize_*` helper
- Any new enum value without corresponding Alembic migration
- Any new model field not added to Pydantic Response schema
- Any new backend field not added to `types.ts`
- Use of `subprocess.run` instead of `asyncio.create_subprocess_exec`
- Direct attribute assignment on SQLAlchemy ORM objects
- Secrets (API keys, passwords) committed to code
- SQL string concatenation (must use parameterized queries)

## Important (should flag)

- New Finding type without confidence scoring
- New agent without registering in orchestrator.py
- Frontend page without subtitle/description under h1
- Missing error handling on external API calls (Shodan, HIBP, etc.)
- Test file missing for new functionality
- Raw `fetch()` in frontend instead of `api.ts` method

## Style (nit)

- Unused imports
- Magic numbers without named constants
- Missing type annotations on function parameters
- Console.log left in frontend code
- Comments that describe what code does (instead of why)
