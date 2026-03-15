Multi-angle design review. Use subagents to investigate each angle in separate context windows.

## Methodology

For each angle, delegate investigation to a subagent:

"use a subagent to investigate [angle] for [area], reading relevant files and reporting findings"

### Angles to Apply

1. **Industry Comparison** — How does this compare to reNgine/BBOT/Burp? Right tools? Better alternatives?
2. **Decision Quality** — Smart or naive/hardcoded logic? What would an expert do differently?
3. **Cross-Agent Data Flow** — Does this read/write data other components use? Intelligence collected but never acted on?
4. **Three-Layer Consistency** — DB model → Schema → types.ts → frontend: any broken pipes?
5. **Reliability** — What happens on failure? Silent or graceful? Retry mechanisms?
6. **Output Quality** — Actionable findings? Evidence? Remediation guidance?
7. **Performance** — Bottlenecks? Wasted effort on low-value targets?
8. **UX / Overload** (frontend only) — Too much info? Clear purpose? 1-2 clicks to complete task?

## Output Format

For each angle, provide:
- **Good:** what works well
- **Broken:** specific issues with file:line references
- **Fix:** prioritized recommendations with effort estimates

End with summary table and three-layer consistency check.

## Area to review: $ARGUMENTS
