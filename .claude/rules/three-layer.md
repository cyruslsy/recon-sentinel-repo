# Three-Layer Consistency (ALWAYS ENFORCE)

Every change must be consistent across all three layers. This is the #1 source of bugs in this project.

| Layer | Files | What to check |
|-------|-------|---------------|
| Database | `enums.py` → `models.py` → Alembic migration | New enum value? `ALTER TYPE ADD VALUE IF NOT EXISTS`. New column? `op.add_column`. |
| Backend | `schemas.py` → `api/*.py` | New field? Add to Pydantic schema AND route's `response_model`. |
| Frontend | `types.ts` → `api.ts` → page component | New field? Add to TypeScript interface, API client, and component. |

After every change, output:
```
## Changes Made
- Files modified: [list]
- Three-layer impact: [enums? schemas? types? migrations?]
- Tests to run: [which test files]
```

If you only touched one layer, explain why the other two don't need changes.

## Verification

- ALWAYS view the file before editing (previous context may be stale)
- ALWAYS view the file after editing to confirm
- Check for dead code after `return` statements
- Verify imports for any new functions/classes
