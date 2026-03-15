---
paths:
  - "backend/app/models/**"
  - "backend/alembic/**"
  - "backend/app/schemas/**"
---
# Database & Schema Rules

## Enum Changes REQUIRE Migrations

Python enum changes auto-propagate. PostgreSQL enum types do NOT.
Every new enum value needs an Alembic migration:
```sql
ALTER TYPE enum_name ADD VALUE IF NOT EXISTS 'new_value';
```
Without this, INSERT will crash on existing databases.

## Alembic Auto-Generate Misses

Auto-generated migrations miss: custom enum types, CHECK constraints, GIN indexes, partial indexes.
Always review generated migrations manually before running.

## Model Conventions

- All models use `UUID_PK()` factory for primary key
- Use `TimestampMixin` for created_at/updated_at
- Foreign keys: always specify `ondelete` (CASCADE or SET NULL)
- Indexes: add for any column used in WHERE clauses or JOINs

## Schema Conventions

- `*Response` — full schema for detail views (includes raw_data, all fields)
- `*Brief` — minimal schema for list views (id, key fields only)
- `*Create` / `*Update` — input schemas with validation
- Every new model field MUST be added to the corresponding Response schema

## Known Broken Pipe

`Finding.raw_data` and `Finding.remediation` exist in the DB model but are NOT in `FindingResponse`.
This is the #1 data visibility bug. Fix is in the master plan Immediate Fixes.
