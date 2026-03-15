"""
Recon Sentinel — Vulnerability Scanning Agent
Tool: Nuclei (ProjectDiscovery)
MITRE: T1190 (Exploit Public-Facing Application)

Improvements over v1 (Round 8+ recommendations):
  1. Per-subdomain scanning — scans ALL discovered hosts, not just root domain
  2. Nuclei -as (automatic scan) — uses Wappalyzer for full tech detection (~3K techs)
     PLUS our TECH_TEMPLATE_MAP as supplementary layer from earlier agents
  3. KEV prioritization — runs CISA Known Exploited Vulnerabilities templates first
  4. WAF-aware rate adaptation — slow scan for WAF-protected hosts, fast for others
  5. Dynamic timeout — scales with target count × template count
  6. Info flood self-correction — re-runs with severity filter if >90% are info

Self-correction patterns:
  - Info flood: >90% info severity → re-run with medium,high,critical filter
  - WAF detection: uses WAF agent results to adapt per-host rate limiting
"""

import hashlib
import json
import logging
import os
import tempfile
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
        self._waf_hosts: set[str] = set()     # Hosts with WAF detected
        self._non_waf_hosts: set[str] = set()  # Hosts without WAF

    async def execute(self) -> list[dict]:
        # ─── Phase 1: Collect ALL targets (per-subdomain scanning) ─
        await self.report_progress(3, "Collecting discovered targets...")
        targets = await self._collect_scan_targets()
        logger.info(f"Vuln phase scanning {len(targets)} targets (root + discovered hosts)")

        # ─── Phase 2: Classify targets by WAF status ──────────
        await self.report_progress(5, "Classifying targets by WAF status...")
        await self._classify_waf_status()

        # ─── Phase 3: Select templates (tech-adaptive + supplementary) ─
        await self.report_progress(8, "Selecting templates based on detected technologies...")
        self._templates = await self._select_templates()
        logger.info(f"Selected {len(self._templates)} supplementary template paths")

        # ─── Phase 4: KEV Priority Scan (fast, critical vulns first) ─
        await self.report_progress(10, "Running KEV priority scan (actively exploited vulns)...")
        kev_results = await self._run_nuclei(targets, mode="kev")
        logger.info(f"KEV scan: {len(kev_results)} results")

        # ─── Phase 5: Automatic scan (Wappalyzer tech detection) ─
        await self.report_progress(30, f"Running automatic tech-based scan on {len(targets)} targets...")
        auto_results = await self._run_nuclei(targets, mode="auto")

        # ─── Phase 6: Supplementary templates from our tech map ─
        if self._templates:
            await self.report_progress(55, f"Running supplementary templates ({len(self._templates)} sets)...")
            supp_results = await self._run_nuclei(targets, mode="templates")
        else:
            supp_results = []

        # ─── Phase 6b: DAST fuzzing (unknown vulns — XSS, SQLi, SSRF, SSTI) ─
        dast_results = []
        if self.config.get("enable_dast", True):
            # Collect parameterized URLs from earlier phases (endpoints, wayback, JS analysis)
            dast_targets = await self._collect_dast_endpoints()
            if dast_targets:
                await self.report_progress(65, f"Running DAST fuzzing on {len(dast_targets)} parameterized endpoints...")
                dast_results = await self._run_nuclei(dast_targets, mode="dast")
                logger.info(f"DAST fuzzing: {len(dast_results)} results from {len(dast_targets)} endpoints")

        # Merge all results
        raw_results = kev_results + auto_results + supp_results + dast_results

        if not raw_results:
            return []

        # ─── Phase 7: Self-correction — info flood check ──────
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
            await self.report_progress(70, "Re-running Nuclei (medium+ only)...")
            raw_results = await self._run_nuclei(targets, mode="auto")

        # ─── Phase 8: Parse into findings ─────────────────────
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

    # ─── Target Collection (per-subdomain scanning) ─────────

    async def _collect_scan_targets(self) -> list[str]:
        """Collect ALL discovered hosts for vuln scanning (not just root domain).
        This is the key improvement: vuln phase now scans every subdomain."""
        targets = set()

        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            # Get subdomains
            result = await db.execute(
                select(Finding.value)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
                .where(Finding.finding_type == FindingType.SUBDOMAIN)
            )
            for r in result.all():
                host = r[0].strip().rstrip("/")
                if not host.startswith("http"):
                    targets.add(f"https://{host}")
                else:
                    targets.add(host)

            # Get web hosts from port findings (HTTP/HTTPS ports)
            result = await db.execute(
                select(Finding.value)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
                .where(Finding.finding_type == FindingType.PORT)
            )
            for r in result.all():
                val = r[0].strip()
                if ":" in val:
                    host, port = val.rsplit(":", 1)
                    if port in ("80", "8080", "8000", "3000"):
                        targets.add(f"http://{host}:{port}" if port != "80" else f"http://{host}")
                    elif port in ("443", "8443"):
                        targets.add(f"https://{host}:{port}" if port != "443" else f"https://{host}")

        # Always include root domain
        root = self.target_value
        if not root.startswith("http"):
            targets.add(f"https://{root}")
        else:
            targets.add(root)

        # Cap to prevent resource exhaustion
        max_targets = self.config.get("max_vuln_targets", 50)
        target_list = sorted(targets)
        if len(target_list) > max_targets:
            logger.warning(f"Capping vuln targets from {len(target_list)} to {max_targets}")

            async with AsyncSessionLocal() as db:
                await self._create_health_event(
                    db, HealthEventType.ANOMALY_DETECTED,
                    f"Vuln target cap reached — scanning {max_targets} of {len(target_list)} hosts",
                    f"Discovered {len(target_list)} web hosts but capping vuln scan at "
                    f"{max_targets} to prevent resource exhaustion. Increase max_vuln_targets "
                    f"in scan config to scan more.",
                )

            target_list = target_list[:max_targets]

        return target_list

    # ─── WAF Classification ───────────────────────────────────

    async def _classify_waf_status(self) -> None:
        """Use WAF Detection Agent findings to classify hosts for rate adaptation."""
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.value, Finding.tags)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
                .where(Finding.tags.any("waf_detected"))
            )
            for val, tags in result.all():
                host = val.strip().rstrip("/")
                if not host.startswith("http"):
                    host = f"https://{host}"
                self._waf_hosts.add(host)

        logger.info(f"WAF classification: {len(self._waf_hosts)} hosts behind WAF")

    # ─── DAST Endpoint Collection ─────────────────────────────

    async def _collect_dast_endpoints(self) -> list[str]:
        """Collect parameterized URLs from earlier phases for DAST fuzzing.
        Nuclei's -dast mode needs URLs with query parameters to fuzz.
        Sources: endpoint findings, wayback URLs, JS-extracted endpoints."""
        endpoints = set()

        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.value)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
                .where(Finding.finding_type.in_([
                    FindingType.ENDPOINT,
                    FindingType.DIRECTORY,
                    FindingType.OTHER,
                ]))
            )
            for r in result.all():
                url = r[0].strip()
                # Only include URLs with query parameters (needed for fuzzing)
                if "?" in url and "=" in url:
                    endpoints.add(url)
                # Also include URLs that look like they accept path parameters
                elif any(pattern in url for pattern in ["/api/", "/v1/", "/v2/", "/search", "/query"]):
                    endpoints.add(url)

        # Cap to prevent excessive fuzzing traffic
        max_dast = self.config.get("max_dast_endpoints", 100)
        endpoint_list = sorted(endpoints)[:max_dast]
        logger.info(f"Collected {len(endpoint_list)} parameterized endpoints for DAST fuzzing")
        return endpoint_list

    # ─── Template Selection ───────────────────────────────────

    async def _select_templates(self) -> list[str]:
        """Select SUPPLEMENTARY Nuclei templates based on technologies found in earlier phases.
        These augment Nuclei's built-in -as (automatic scan) mode, which uses Wappalyzer
        for ~3,000 technologies. Our map catches tech indicators from non-web agents
        (port scan, OSINT, threat intel) that Wappalyzer wouldn't see."""
        templates = set()

        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.raw_data, Finding.tags)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
            )
            rows = result.all()

            for raw_data, tags in rows:
                if tags:
                    for tag in tags:
                        tag_lower = tag.lower()
                        for tech, paths in TECH_TEMPLATE_MAP.items():
                            if tech in tag_lower:
                                templates.update(paths)

                if raw_data and isinstance(raw_data, dict):
                    for tech in raw_data.get("tech_detected", []):
                        tech_lower = tech.lower()
                        for key, paths in TECH_TEMPLATE_MAP.items():
                            if key in tech_lower:
                                templates.update(paths)

        # C5: Also use shared tech_context for broader stack coverage
        try:
            from app.agents.tech_context import get_scan_tech_context
            tech_ctx = await get_scan_tech_context(self.scan_id)
            for stack in tech_ctx.all_active_stacks:
                stack_lower = stack.lower()
                for key, paths in TECH_TEMPLATE_MAP.items():
                    if key in stack_lower:
                        templates.update(paths)
            if tech_ctx.all_active_stacks:
                logger.info(f"C5: Tech-context stacks enriched templates: {tech_ctx.all_active_stacks}")
        except Exception as e:
            logger.warning(f"C5: Tech-context template enrichment failed: {e}")

        # Don't add defaults — the -as mode handles that via Wappalyzer
        # Only return supplementary templates from our tech map
        return sorted(templates)

    # ─── Nuclei Execution (multi-mode) ────────────────────────

    async def _run_nuclei(self, targets: list[str], mode: str = "auto") -> list[dict]:
        """Run Nuclei with support for multiple modes and target lists.

        Modes:
          - kev: Run KEV (Known Exploited Vulnerabilities) templates only — fast, critical-first
          - auto: Use Nuclei's -as (automatic scan with Wappalyzer tech detection)
          - templates: Run our supplementary tech-specific templates
        """
        # Write targets to a temp file for -l flag
        targets_file = None
        try:
            fd, targets_file = tempfile.mkstemp(suffix=".txt", prefix="nuclei_targets_")
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(targets))

            # Base command
            cmd = [
                "nuclei",
                "-l", targets_file,
                "-json",
                "-silent",
                "-no-color",
                "-bulk-size", "25",
                "-concurrency", str(self.config.get("concurrency", 10)),
                "-timeout", "10",
                "-retries", "1",
            ]

            # WAF-aware rate limiting: if any targets have WAF, use slower rate
            if self._waf_hosts:
                waf_ratio = len(self._waf_hosts) / max(len(targets), 1)
                if waf_ratio > 0.5:
                    # Majority WAF — use stealth rate
                    rate = self.config.get("waf_rate_limit", 15)
                    cmd.extend(["-rate-limit", str(rate)])
                    logger.info(f"WAF-aware: using stealth rate {rate} req/s ({len(self._waf_hosts)} WAF hosts)")
                else:
                    # Mixed — use moderate rate
                    rate = self.config.get("rate_limit", 30)
                    cmd.extend(["-rate-limit", str(rate)])
            else:
                rate = self.config.get("rate_limit", 50)
                cmd.extend(["-rate-limit", str(rate)])

            # Mode-specific flags
            if mode == "kev":
                cmd.extend(["-tags", "kev,vkev"])
                cmd.extend(["-severity", "critical,high"])
            elif mode == "auto":
                cmd.append("-as")  # Wappalyzer automatic tech detection
            elif mode == "templates":
                for tpl in self._templates:
                    cmd.extend(["-t", tpl])
            elif mode == "dast":
                cmd.append("-dast")  # DAST fuzzing for unknown XSS, SQLi, SSRF, SSTI, CRLF
                cmd.extend(["-concurrency", "5"])  # Lower concurrency for fuzzing (more traffic per target)

            # Add severity filter if set (self-correction)
            if self._severity_filter:
                cmd.extend(["-severity", self._severity_filter])

            # Exclude noisy templates (but NOT for dast mode — fuzzing needs fuzz tag)
            if mode != "dast":
                exclude_tags = "dos,fuzz"
                cmd.extend(["-exclude-tags", exclude_tags])
            else:
                cmd.extend(["-exclude-tags", "dos"])

            # Dynamic timeout: scale with target count
            # Base 300s + 10s per target, capped at 1800s (30 min)
            dynamic_timeout = min(300 + len(targets) * 10, 1800)

            try:
                result = await self.run_command(cmd, timeout=dynamic_timeout, parse_json=True)
                if result["parsed"]:
                    return result["parsed"]
                return []
            except TimeoutError:
                logger.warning(f"Nuclei ({mode}) timed out after {dynamic_timeout}s on {len(targets)} targets")
                return []
            except Exception as e:
                logger.error(f"Nuclei ({mode}) failed: {e}")
                return []

        finally:
            # Clean up temp file
            if targets_file and os.path.exists(targets_file):
                try:
                    os.unlink(targets_file)
                except OSError:
                    pass


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.vuln.run_vuln_agent", soft_time_limit=5400, time_limit=5700)
def run_vuln_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    agent = VulnAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
