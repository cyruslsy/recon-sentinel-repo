Run both validation agents on recent changes or specified files.

1. Determine what to validate:
   - If $ARGUMENTS specified: validate those files
   - Otherwise: `git diff --name-only HEAD` to find recently modified files

2. Run project-rules-checker agent:
   "Use the project-rules-checker agent to validate these files: [list]"

3. Run code-reviewer agent:
   "Use the code-reviewer agent to review these files: [list]"

4. Report combined results.

## Files to validate: $ARGUMENTS
