"""
Recon Sentinel — Vulnerability Scanning Agent
Tool: Nuclei (ProjectDiscovery)
MITRE: T1190 (Exploit Public-Facing Application)

Selects Nuclei templates based on technologies detected in the active phase:
  - WordPress → wordpress/ templates
  - Apache → apache/ templates  
  - Exposed .env → exposures/ templates
  - Default → cves/, misconfiguration/, exposures/

Self-correction: If >90% of results are "info" severity, re-run with
severity filter to focus on medium+ findings.
"""

import hashlib
import json
import logging
import uuid

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.models import Finding
from app.models.enums import FindingSeverity, FindingType, ScanPhase, HealthEventType

logger = logging.getLogger(__name__)

# Technology → Nuclei template directory mapping
TECH_TEMPLATE_MAP = {
    "wordpress": ["http/technologies/wordpress/", "http/vulnerabilities/wordpress/"],
    "wp-admin": ["http/technologies/wordpress/", "http/vulnerabilities/wordpress/"],
    "joomla": ["http/technologies/joomla/"],
    "drupal": ["http/technologies/drupal/"],
    "apache": ["http/misconfiguration/apache/"],
    "nginx": ["http/misconfiguration/nginx/"],
    "iis": ["http/misconfiguration/iis/"],
    "php": ["http/technologies/php/"],
    "laravel": ["http/technologies/laravel/"],
    "django": ["http/technologies/django/"],
    "express": ["http/technologies/express/"],
    "spring": ["http/technologies/spring/"],
    "tomcat": ["http/misconfiguration/tomcat/", "http/vulnerabilities/apache/"],
    "jenkins": ["http/vulnerabilities/jenkins/"],
    "grafana": ["http/vulnerabilities/grafana/"],
    "gitlab": ["http/vulnerabilities/gitlab/"],
    "confluence": ["http/vulnerabilities/atlassian/"],
    "jira": ["http/vulnerabilities/atlassian/"],
}

# Default templates when no specific tech is detected
DEFAULT_TEMPLATES = [
    "http/cves/",
    "http/misconfiguration/",
    "http/exposures/",
    "http/vulnerabilities/generic/",
    "network/cves/",
]

# Map Nuclei severity strings to our enum
SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
    "unknown": FindingSeverity.INFO,
}

# Map Nuclei template tags to MITRE techniques
TAG_MITRE_MAP = {
    "cve": ["T1190"],
    "rce": ["T1190", "T1059"],
    "sqli": ["T1190"],
    "xss": ["T1189"],
    "ssrf": ["T1190"],
    "lfi": ["T1190"],
    "auth-bypass": ["T1078"],
    "default-login": ["T1078"],
    "exposure": ["T1590"],
    "misconfig": ["T1190"],
    "unauth": ["T1078"],
}


class VulnAgent(BaseAgent):
    agent_type = "vuln"
    agent_name = "Vulnerability Scanner Agent"
    phase = ScanPhase.VULN
    mitre_tags = ["T1190"]
    max_retries = 1  # Nuclei is expensive — limit retries

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._severity_filter: str | None = None
        self._templates: list[str] = []

    async def execute(self) -> list[dict]:
        target = self.target_value
        if not target.startswith("http"):
            target = f"https://{target}"

        # ─── Phase 1: Select templates based on tech detection ─
        await self.report_progress(5, "Selecting templates based on detected technologies...")
        self._templates = await self._select_templates()
        logger.info(f"Selected {len(self._templates)} template paths for {target}")

        # ─── Phase 2: Run Nuclei ──────────────────────────────
        await self.report_progress(15, f"Running Nuclei ({len(self._templates)} template sets)...")
        raw_results = await self._run_nuclei(target)

        if not raw_results:
            return []

        # ─── Phase 3: Self-correction — info flood check ──────
        info_count = sum(1 for r in raw_results if r.get("severity", "").lower() == "info")
        if len(raw_results) > 10 and info_count / len(raw_results) > 0.90:
            logger.info(f"Info flood detected: {info_count}/{len(raw_results)} are info-severity")

            async with AsyncSessionLocal() as db:
                await self._create_health_event(
                    db, HealthEventType.SELF_CORRECTION,
                    "Info flood detected — re-running with severity filter",
                    f"{info_count}/{len(raw_results)} results are info-severity. "
                    f"Re-running with -severity medium,high,critical.",
                )

            self._severity_filter = "medium,high,critical"
            await self.report_progress(60, "Re-running Nuclei (medium+ only)...")
            raw_results = await self._run_nuclei(target)

        # ─── Phase 4: Parse into findings ─────────────────────
        await self.report_progress(85, f"Processing {len(raw_results)} results...")
        findings = []
        seen_fingerprints = set()

        for r in raw_results:
            template_id = r.get("template-id", r.get("templateID", "unknown"))
            matched_at = r.get("matched-at", r.get("matchedAt", target))
            severity_str = r.get("info", {}).get("severity", r.get("severity", "info")).lower()
            name = r.get("info", {}).get("name", r.get("name", template_id))
            description = r.get("info", {}).get("description", "")
            tags = r.get("info", {}).get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            reference = r.get("info", {}).get("reference", [])
            curl_command = r.get("curl-command", "")

            # Deduplicate by (template_id, matched_at)
            fp = hashlib.sha256(f"vuln:{template_id}:{matched_at}".encode()).hexdigest()[:32]
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)

            # Map severity
            severity = SEVERITY_MAP.get(severity_str, FindingSeverity.INFO)

            # Map tags to MITRE
            mitre_ids = set(self.mitre_tags)
            for tag in tags:
                tag_lower = tag.lower()
                for key, techniques in TAG_MITRE_MAP.items():
                    if key in tag_lower:
                        mitre_ids.update(techniques)

            findings.append({
                "finding_type": FindingType.VULNERABILITY,
                "severity": severity,
                "value": f"{template_id} — {matched_at}",
                "detail": f"{name}. {description[:200]}" if description else name,
                "mitre_technique_ids": sorted(mitre_ids),
                "fingerprint": fp,
                "tags": tags,
                "raw_data": {
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "severity": severity_str,
                    "name": name,
                    "description": description[:500],
                    "tags": tags,
                    "reference": reference[:5] if isinstance(reference, list) else [],
                    "curl_command": curl_command[:500],
                    "matcher_name": r.get("matcher-name", ""),
                    "extracted_results": r.get("extracted-results", [])[:10],
                },
            })

        return findings

    # ─── Template Selection ───────────────────────────────────

    async def _select_templates(self) -> list[str]:
        """Select Nuclei templates based on technologies found in earlier phases."""
        templates = set()

        # Check findings from this scan for tech indicators
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.raw_data, Finding.tags)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
            )
            rows = result.all()

            for raw_data, tags in rows:
                # Check tags
                if tags:
                    for tag in tags:
                        tag_lower = tag.lower()
                        for tech, paths in TECH_TEMPLATE_MAP.items():
                            if tech in tag_lower:
                                templates.update(paths)

                # Check raw_data for tech_detected
                if raw_data and isinstance(raw_data, dict):
                    for tech in raw_data.get("tech_detected", []):
                        tech_lower = tech.lower()
                        for key, paths in TECH_TEMPLATE_MAP.items():
                            if key in tech_lower:
                                templates.update(paths)

        # If no specific tech found, use defaults
        if not templates:
            templates = set(DEFAULT_TEMPLATES)

        # Always include generic CVE and exposure checks
        templates.add("http/cves/")
        templates.add("http/exposures/")

        return sorted(templates)

    # ─── Nuclei Execution ─────────────────────────────────────

    async def _run_nuclei(self, target: str) -> list[dict]:
        """Run Nuclei with selected templates."""
        cmd = [
            "nuclei",
            "-u", target,
            "-json",
            "-silent",
            "-no-color",
            "-rate-limit", str(self.config.get("rate_limit", 50)),
            "-bulk-size", "25",
            "-concurrency", "10",
            "-timeout", "10",
            "-retries", "1",
        ]

        # Add template paths
        for tpl in self._templates:
            cmd.extend(["-t", tpl])

        # Add severity filter if set (self-correction)
        if self._severity_filter:
            cmd.extend(["-severity", self._severity_filter])

        # Exclude noisy templates
        cmd.extend([
            "-exclude-tags", "dos,fuzz",
            "-exclude-severity", "info" if self._severity_filter else "",
        ])

        # Clean empty args
        cmd = [c for c in cmd if c]

        try:
            result = await self.run_command(cmd, timeout=600, parse_json=True)
            if result["parsed"]:
                return result["parsed"]
            return []
        except TimeoutError:
            logger.warning(f"Nuclei timed out after 600s on {target}")
            return []
        except Exception as e:
            logger.error(f"Nuclei failed: {e}")
            return []


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.vuln.run_vuln_agent")
def run_vuln_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    agent = VulnAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
