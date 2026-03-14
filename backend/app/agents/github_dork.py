"""
Recon Sentinel — GitHub Dorking Agent
Searches GitHub's code search API for:
  - Leaked API keys, tokens, credentials referencing the target domain
  - Configuration files with internal endpoints
  - Source code referencing internal infrastructure
  - Exposed .env files, database connection strings

Phase: Passive
MITRE: T1593 (Search Open Websites/Domains), T1552 (Unsecured Credentials)
Requires: GitHub personal access token in API key store (service_name="github")
"""

import asyncio
import hashlib
import logging

import httpx

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingType, FindingSeverity

logger = logging.getLogger(__name__)

# GitHub code search dorks — each targets a different leak vector
DORK_TEMPLATES = [
    # Credentials
    ('password "{domain}"', "password_leak", FindingSeverity.HIGH),
    ('api_key "{domain}"', "api_key_leak", FindingSeverity.HIGH),
    ('secret "{domain}"', "secret_leak", FindingSeverity.HIGH),
    ('token "{domain}"', "token_leak", FindingSeverity.HIGH),
    ('authorization "{domain}"', "auth_header", FindingSeverity.MEDIUM),

    # Config files
    ('filename:.env "{domain}"', "env_file", FindingSeverity.HIGH),
    ('filename:.yml "{domain}"', "yaml_config", FindingSeverity.MEDIUM),
    ('filename:.json "{domain}"', "json_config", FindingSeverity.MEDIUM),
    ('filename:config "{domain}"', "config_file", FindingSeverity.MEDIUM),
    ('filename:docker-compose "{domain}"', "docker_config", FindingSeverity.MEDIUM),

    # Infrastructure
    ('"{domain}" extension:sql', "sql_dump", FindingSeverity.HIGH),
    ('"{domain}" extension:pem', "private_key", FindingSeverity.CRITICAL),
    ('"{domain}" extension:key', "key_file", FindingSeverity.CRITICAL),
    ('"{domain}" internal', "internal_ref", FindingSeverity.LOW),
    ('"{domain}" staging OR dev OR test', "non_prod_ref", FindingSeverity.LOW),

    # Specific patterns
    ('"{domain}" AKIA', "aws_key", FindingSeverity.CRITICAL),
    ('"{domain}" ghp_', "github_token", FindingSeverity.CRITICAL),
    ('"{domain}" sk-', "api_secret", FindingSeverity.HIGH),
    ('"{domain}" jdbc:', "db_connection", FindingSeverity.HIGH),
    ('"{domain}" mongodb://', "mongo_connection", FindingSeverity.HIGH),
]


class GitHubDorkAgent(BaseAgent):
    agent_type = "github_dork"
    agent_name = "GitHub Code Search (Dorking)"
    mitre_tags = ["T1593", "T1552"]
    max_retries = 1

    async def execute(self) -> list[dict]:
        target = self.target_value
        findings = []

        # Get GitHub token from config or API key store
        github_token = self.config.get("github_token", "")
        if not github_token:
            logger.warning("No GitHub token configured — using unauthenticated search (rate-limited)")

        await self.report_progress(3, "Loading tech context from previous agents...")

        # Build tech-adaptive dork list
        from app.agents.tech_context import get_scan_tech_context
        from app.models.enums import FindingSeverity as FS
        tech_ctx = await get_scan_tech_context(self.scan_id)

        SEVERITY_MAP = {"CRITICAL": FS.CRITICAL, "HIGH": FS.HIGH, "MEDIUM": FS.MEDIUM, "LOW": FS.LOW, "INFO": FS.INFO}

        # ─── Tiered execution: prioritize high-value dorks ──────────
        # Tier 1: Base dorks (always run — 20 queries, proven value)
        # Tier 2: Tech-detected dorks (only for matched stacks — high precision)
        # Tier 3: Always-check dorks (CRITICAL severity only — broad sweep)
        # Budget: stop at MAX_DORKS to respect rate limits

        MAX_DORKS = 40 if github_token else 25  # Stay within rate limit budget

        # Tier 1: base dorks
        tier1 = list(DORK_TEMPLATES)

        # Tier 2: dorks from stacks matched by actual detected tech (high precision)
        tier2 = []
        for stack_name in tech_ctx.matched_stacks:
            stack = tech_ctx._get_stack(stack_name)
            for template, dtype, sev_str in stack.get("github_dorks", []):
                tier2.append((template, dtype, SEVERITY_MAP.get(sev_str, FS.HIGH)))

        # Tier 3: CRITICAL-only dorks from always-check stacks (broad sweep)
        tier3 = []
        for stack_name in tech_ctx.always_check:
            if stack_name in tech_ctx.matched_stacks:
                continue  # already in tier 2
            stack = tech_ctx._get_stack(stack_name)
            for template, dtype, sev_str in stack.get("github_dorks", []):
                if sev_str == "CRITICAL":
                    tier3.append((template, dtype, FS.CRITICAL))

        # Merge tiers, deduplicate, cap at budget
        seen = set()
        prioritized_dorks = []
        for dork in tier1 + tier2 + tier3:
            if dork[0] not in seen:
                seen.add(dork[0])
                prioritized_dorks.append(dork)
            if len(prioritized_dorks) >= MAX_DORKS:
                break

        logger.info(
            f"GitHub dorking {target}: tier1={len(tier1)} base, "
            f"tier2={len(tier2)} detected, tier3={len(tier3)} sweep → "
            f"{len(prioritized_dorks)} total (budget: {MAX_DORKS})"
        )

        await self.report_progress(5, f"Searching {len(prioritized_dorks)} dork patterns...")

        headers = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        rate_limit_hits = 0
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            for i, (dork_template, dork_type, base_severity) in enumerate(prioritized_dorks):
                query = dork_template.replace("{domain}", target)
                pct = 5 + int((i / len(prioritized_dorks)) * 85)
                await self.report_progress(pct, f"Searching: {dork_type}...")

                try:
                    resp = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": 5},
                    )

                    if resp.status_code == 403:
                        rate_limit_hits += 1
                        if rate_limit_hits >= 3:
                            logger.warning("GitHub rate limited 3x — stopping dorks")
                            break
                        # Back off and retry once instead of immediately giving up
                        retry_after = int(resp.headers.get("Retry-After", "60"))
                        wait = min(retry_after, 65)
                        logger.warning(f"GitHub rate limited — waiting {wait}s ({rate_limit_hits}/3)")
                        await asyncio.sleep(wait)
                        continue
                    if resp.status_code != 200:
                        continue

                    data = resp.json()
                    total = data.get("total_count", 0)

                    if total > 0:
                        items = data.get("items", [])
                        for item in items[:3]:  # Max 3 results per dork
                            repo = item.get("repository", {}).get("full_name", "unknown")
                            path = item.get("path", "")
                            html_url = item.get("html_url", "")

                            # Escalate severity for certain repo patterns
                            severity = base_severity
                            if any(kw in repo.lower() for kw in [target.split(".")[0], "internal", "private"]):
                                severity = FindingSeverity.CRITICAL if severity == FindingSeverity.HIGH else severity

                            findings.append({
                                "finding_type": FindingType.CREDENTIAL,
                                "severity": severity,
                                "value": f"GitHub: {dork_type} in {repo}/{path}",
                                "detail": (
                                    f"GitHub code search found {total} result(s) for '{query}'. "
                                    f"Top hit: {repo}/{path}. "
                                    f"URL: {html_url}"
                                ),
                                "mitre_technique_ids": ["T1593", "T1552"],
                                "fingerprint": hashlib.sha256(f"github:{dork_type}:{repo}:{path}".encode()).hexdigest()[:32],
                                "raw_data": {
                                    "query": query,
                                    "dork_type": dork_type,
                                    "total_results": total,
                                    "repo": repo,
                                    "path": path,
                                    "url": html_url,
                                },
                                "tags": ["github_dork", dork_type],
                            })

                except httpx.RequestError as e:
                    logger.warning(f"GitHub search error for {dork_type}: {e}")
                    continue

                # Respect GitHub rate limit: 10 requests per minute for unauthenticated
                await asyncio.sleep(6 if not github_token else 2)

        if not findings:
            findings.append({
                "finding_type": FindingType.CREDENTIAL,
                "severity": FindingSeverity.INFO,
                "value": f"GitHub dorking: no leaks found for {target}",
                "detail": f"Searched {len(DORK_TEMPLATES)} dork patterns. No public code referencing {target} with credentials or sensitive config.",
                "mitre_technique_ids": ["T1593"],
                "fingerprint": hashlib.sha256(f"github:clean:{target}".encode()).hexdigest()[:32],
                "raw_data": {"dorks_searched": len(DORK_TEMPLATES), "results": 0},
                "tags": ["github_dork", "clean"],
            })

        await self.report_progress(100, f"GitHub dorking complete: {len(findings)} findings")
        return findings


@celery_app.task(name="app.agents.github_dork.run_github_dork_agent")
def run_github_dork_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(GitHubDorkAgent(scan_id, target_value, project_id, config).run())
