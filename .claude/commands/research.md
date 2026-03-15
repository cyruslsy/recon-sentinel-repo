Research phase for a feature or master plan item. Investigate the codebase and produce a spec.

Use subagents to investigate each area separately to keep main context clean.

## Steps

1. Read `docs/MASTER-PLAN.md` to understand the item context
2. Use subagents to investigate:
   - "use a subagent to investigate how the current [relevant system] works, reading all related files"
   - "use a subagent to check what types, schemas, and models already exist for this feature"
   - "use a subagent to find all files that would need changes for this feature"
3. Synthesize findings into a spec file: `docs/specs/SPEC-$ARGUMENTS.md`
4. The spec MUST include:
   - Current state (what exists today)
   - Target state (what we're building)
   - Files to modify (with three-layer mapping: DB → Schema → Types → Frontend)
   - Migration needed? (exact DDL if yes)
   - Dependencies on other items
   - Test plan (what tests verify this works)
   - Risks and edge cases

## Output

Save spec to `docs/specs/SPEC-$ARGUMENTS.md` and summarize key findings.
Then say: "Spec complete. Start a fresh session and run `/plan $ARGUMENTS` to create the execution plan."

## Item to research: $ARGUMENTS
