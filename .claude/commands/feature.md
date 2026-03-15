Entry point for new feature requests. DO NOT start implementing. First understand, then confirm, then route.

## Step 1: Summarize what you heard

Restate the user's request in a structured format:

```
## Feature Request Summary
**What:** [one sentence — what the user wants]
**Why:** [why this matters — infer from context, or say "unclear, will ask"]
**Scope:** [what parts of the system are likely affected]
**Complexity estimate:** Quick (1-2 files) | Standard (3-10 files) | Full (10+ files, new models, UI changes)
```

## Step 2: Ask clarifying questions

Before proceeding, ask the user questions to fill gaps. Use the most efficient format:

Focus on questions that change WHAT gets built, not HOW:
- What's the expected behavior? (not obvious from the request)
- What triggered this? (pain point, client feedback, competitive gap?)
- Any constraints? (must work with existing X, can't break Y)
- Who uses this? (pentester during scan? CISO reading report? both?)
- What does "done" look like? (how do we verify it works?)

Skip questions where the answer is obvious from the codebase or master plan.

## Step 3: Confirm and route

After gathering answers, present the refined request:

```
## Refined Feature Request
**What:** [updated one sentence]
**Why:** [now clear]
**Affected layers:**
  - DB: [new model? new field? migration needed?]
  - Backend: [new endpoint? new agent? orchestrator change?]
  - Frontend: [new page? new component? existing page change?]
**Complexity:** Quick | Standard | Full

## Recommended approach:
- Quick → I'll implement directly. Proceed? (y/n)
- Standard → I'll research the codebase first, then create a plan. Proceed? (y/n)
- Full → I'll do full RPI: research → plan → you review → implement. Proceed? (y/n)
```

Wait for user confirmation before doing ANY work.

## Step 4: Execute

- If Quick: run `/implement` directly
- If Standard: run `/research` → `/plan` → `/implement`
- If Full: run `/research` (with subagents) → `/plan` (with PM/UX/Eng split if UI-involved) → user reviews plan → `/implement`

## The user's request: $ARGUMENTS
