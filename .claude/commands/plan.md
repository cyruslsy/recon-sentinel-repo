Plan phase for a feature. Convert the research spec into concrete implementation steps.

## Steps

1. Read the spec: `docs/specs/SPEC-$ARGUMENTS.md`
2. Break into ordered, atomic tasks. Each task should be completable in one focused session.
3. For each task, specify:
   - Exact files to create or modify
   - What to change (with enough detail that /implement can execute it)
   - Verification command (test, curl, docker logs)
4. Order tasks by dependency — if task B depends on task A's output, A goes first.
5. Save plan to `docs/specs/PLAN-$ARGUMENTS.md`

## Plan Format

```markdown
# Plan: [Item ID]

## Task 1: [name]
- Files: [list]
- Changes: [what to do]
- Verify: [command to confirm it works]
- Depends: none

## Task 2: [name]
- Files: [list]
- Changes: [what to do]
- Verify: [command]
- Depends: Task 1
```

## For Ralph Loop Integration

If this item is complex (3+ tasks), end with:
"Plan complete. To execute autonomously, run:
`/ralph-loop 'Execute PLAN-$ARGUMENTS.md task by task. Run verification after each. Output <promise>COMPLETE</promise> when all tasks pass.' --max-iterations 20`"

## Item to plan: $ARGUMENTS
