Implement a master plan item. The argument should be the item ID (e.g., "B1", "D4", "E3").

Read CLAUDE.md for the master plan overview, then implement the item following these steps:

1. Identify the item from the master plan in CLAUDE.md
2. Read ALL files that will be affected (view before editing)
3. Plan the three-layer changes:
   - DB: models.py + enums.py + migration needed?
   - Schema: schemas.py changes?
   - Types: frontend/src/lib/types.ts changes?
   - Frontend: any page.tsx changes?
   - Backend: which agent/task files?
4. Implement changes in dependency order: DB → Schema → Backend → Types → Frontend
5. After each file edit, view it to confirm the edit landed correctly
6. Run relevant tests
7. Output the post-change summary:
   - Files modified
   - Three-layer impact
   - Migration needed?
   - Tests to run

Item to implement: $ARGUMENTS
