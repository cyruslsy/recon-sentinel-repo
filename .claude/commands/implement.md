Implement a master plan item or feature. After implementation, automatically validate with agents.

## Step 1: Determine complexity

1. If `docs/specs/PLAN-$ARGUMENTS.md` exists → execute the plan task by task
2. If `docs/specs/SPEC-$ARGUMENTS.md` exists → create plan first, then execute
3. If item is in `docs/MASTER-PLAN.md` → read the item details, implement directly
4. Otherwise → simple enough? implement directly. Complex? run `/research` first.

## Step 2: Implement

- Read ALL files that will be affected (view before editing)
- Implement in dependency order: DB → Schema → Backend → Types → Frontend
- After each file edit, view to confirm
- Run relevant tests after each significant change

## Step 3: Validate (MANDATORY — do not skip)

After implementation is complete, run BOTH agents:

1. "Use the project-rules-checker agent to validate all files I modified in this session"
2. "Use the code-reviewer agent to review all files I modified in this session"

If either agent finds CRITICAL issues, fix them before outputting the summary.

## Step 4: Summary

```
## Changes Made
- Files modified: [list]
- Three-layer impact: [what changed at each layer]
- Tests run: [results]
- Code review: [X critical, Y warnings, Z nits]
- Rules check: [X passed, Y failed]
```

## Item to implement: $ARGUMENTS
