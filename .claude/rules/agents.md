---
paths:
  - "backend/app/agents/**"
---
# Agent Development Rules

## Agent Pattern

```python
class MyAgent(BaseAgent):
    agent_type = "my_agent"
    agent_name = "My Agent"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1190"]

    async def execute(self) -> list[dict]:
        findings = []
        findings.append({
            "finding_type": FindingType.VULNERABILITY,
            "severity": FindingSeverity.HIGH,
            "value": "what was found",
            "detail": "description with evidence",
            "mitre_technique_ids": ["T1190"],
            "fingerprint": hashlib.sha256(f"unique:{key}".encode()).hexdigest()[:32],
            "raw_data": {"evidence": "...", "source": "tool_name"},
            "tags": ["tag1"],
        })
        return findings
```

Bottom of file: `@celery_app.task(name="app.agents.my_agent.run_my_agent")`
Register in `orchestrator.py` `_get_passive_agents()` / `_get_active_agents()` / `_get_vuln_agents()`.

## External Tool Calls

- Use `self.run_command(cmd, timeout=300)` — NEVER `subprocess.run`
- Tools run in own process group (`start_new_session=True`)
- Always set a timeout. Default 300s (5 min).

## Self-Correction

- 11 patterns in `corrections.py`: Custom404, WAF, RateLimit, RedirectLoop, DNSWildcard, etc.
- Override `self_correct(error_context)` to add agent-specific correction
- `max_retries` defaults to 1. Increase for agents that benefit from retry.

## Tech Context

- `tech_context.py` has 24 tech stacks, 127 dork templates
- Use `get_scan_tech_context(db, scan_id)` to get detected tech for the current scan
- Always-check stacks (7): ai_llm, ai_agents, cicd, databases, comms, observability, secrets_mgmt

## Finding Quality

- Set `confidence` (0-100): 90+ = verified, 70-89 = strong indicator, 50-69 = pattern match, <50 = heuristic
- Include evidence in `raw_data`: curl commands, response snippets, matched patterns
- Use specific `FindingType` — never use `OTHER` if a better type exists
