"""
Recon Sentinel — URL Discovery Agent (gau)
Multi-source URL collection: Wayback Machine, Common Crawl, OTX, URLScan.
Replaces single-source Wayback CDX API with gau for broader coverage.

Phase: Passive
MITRE: T1593 (Search Open Websites/Domains)
"""

import hashlib
import logging
from collections import Counter
from urllib.parse import urlparse

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingType, FindingSeverity

logger = logging.getLogger(__name__)

# Interesting file patterns that often contain secrets or sensitive data
INTERESTING_EXTENSIONS = {
    ".env", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".json", ".xml", ".sql", ".bak", ".backup", ".old", ".orig",
    ".log", ".txt", ".csv", ".key", ".pem", ".p12", ".pfx",
    ".htpasswd", ".htaccess", ".DS_Store", ".git/config",
    ".svn/entries", ".swp", ".swo",
}

INTERESTING_PATHS = {
    "/admin", "/wp-admin", "/wp-login", "/phpmyadmin", "/cpanel",
    "/api/", "/graphql", "/swagger", "/openapi", "/.well-known",
    "/debug", "/trace", "/actuator", "/metrics", "/health",
    "/config", "/settings", "/setup", "/install",
    "/backup", "/dump", "/export", "/download",
    "/internal", "/private", "/staging", "/dev", "/test",
    "/.git/", "/.svn/", "/.env", "/robots.txt", "/sitemap.xml",
}

URL_CAP = 10000

class WaybackAgent(BaseAgent):
    agent_type = "wayback"
    agent_name = "URL Discovery Agent (gau)"
    mitre_tags = ["T1593"]
    max_retries = 1

    async def execute(self) -> list[dict]:
        target = self.target_value
        findings = []

        # ─── Phase 1: Run gau for multi-source URL collection ──
        await self.report_progress(10, "Running gau (multi-source URL discovery)...")
        urls = await self._run_gau(target)

        if not urls:
            logger.info(f"No archived URLs found for {target}")
            return findings

        await self.report_progress(30, f"Found {len(urls)} URLs from gau")

        # ─── Phase 2: Classify interesting URLs ───────────────
        await self.report_progress(40, "Classifying URLs...")
        interesting_files = []
        interesting_endpoints = []
        all_paths = []

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            all_paths.append(path)

            for ext in INTERESTING_EXTENSIONS:
                if path.endswith(ext):
                    interesting_files.append(url)
                    break

            for pattern in INTERESTING_PATHS:
                if pattern in path:
                    interesting_endpoints.append(url)
                    break

        # Deduplicate by path
        seen_paths: set[str] = set()
        unique_files = []
        for url in interesting_files:
            path = urlparse(url).path
            if path not in seen_paths:
                seen_paths.add(path)
                unique_files.append(url)

        seen_paths = set()
        unique_endpoints = []
        for url in interesting_endpoints:
            path = urlparse(url).path
            if path not in seen_paths:
                seen_paths.add(path)
                unique_endpoints.append(url)

        # ─── Phase 3: Report interesting files ────────────────
        await self.report_progress(60, f"Found {len(unique_files)} sensitive files, {len(unique_endpoints)} interesting endpoints")

        for url in unique_files[:50]:
            path = urlparse(url).path
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
            severity = FindingSeverity.HIGH if ext in {".env", ".key", ".pem", ".htpasswd", ".sql", ".bak"} else FindingSeverity.MEDIUM

            findings.append({
                "finding_type": FindingType.HISTORICAL,
                "severity": severity,
                "value": f"Archived sensitive file: {path}",
                "detail": f"Discovered via gau: {url}. File type '{ext}' may contain credentials, configuration, or backup data.",
                "mitre_technique_ids": ["T1593"],
                "fingerprint": hashlib.sha256(f"wayback:file:{path}".encode()).hexdigest()[:32],
                "raw_data": {"url": url, "path": path, "extension": ext, "source": "gau"},
                "tags": ["historical", "sensitive_file"],
            })

        for url in unique_endpoints[:50]:
            path = urlparse(url).path
            severity = FindingSeverity.MEDIUM if any(p in path for p in {"/admin", "/debug", "/actuator", "/.git/"}) else FindingSeverity.INFO

            findings.append({
                "finding_type": FindingType.HISTORICAL,
                "severity": severity,
                "value": f"Archived endpoint: {path}",
                "detail": f"Discovered via gau: {url}. Endpoint may still be accessible or reveal architecture information.",
                "mitre_technique_ids": ["T1593"],
                "fingerprint": hashlib.sha256(f"wayback:endpoint:{path}".encode()).hexdigest()[:32],
                "raw_data": {"url": url, "path": path, "source": "gau"},
                "tags": ["historical", "endpoint"],
            })

        # ─── Phase 4: URL pattern analysis ────────────────────
        await self.report_progress(80, "Analyzing URL patterns...")

        tech_indicators = Counter()
        for path in all_paths:
            if "/wp-" in path or "/wordpress" in path:
                tech_indicators["WordPress"] += 1
            if "/joomla" in path or "/administrator" in path:
                tech_indicators["Joomla"] += 1
            if "/drupal" in path or "/sites/default" in path:
                tech_indicators["Drupal"] += 1
            if ".php" in path:
                tech_indicators["PHP"] += 1
            if ".asp" in path or ".aspx" in path:
                tech_indicators["ASP.NET"] += 1
            if "/api/v" in path or "/graphql" in path:
                tech_indicators["API"] += 1
            if ".jsp" in path or "/servlet" in path:
                tech_indicators["Java/Tomcat"] += 1

        if tech_indicators:
            top_tech = tech_indicators.most_common(5)
            findings.append({
                "finding_type": FindingType.TECH_STACK,
                "severity": FindingSeverity.INFO,
                "value": f"Historical tech stack: {', '.join(t[0] for t in top_tech)}",
                "detail": f"URL pattern analysis across {len(urls)} URLs suggests: {', '.join(f'{t[0]} ({t[1]} URLs)' for t in top_tech)}",
                "mitre_technique_ids": ["T1592"],
                "fingerprint": hashlib.sha256(f"wayback:tech:{target}".encode()).hexdigest()[:32],
                "raw_data": {"tech_indicators": dict(tech_indicators), "total_urls": len(urls)},
                "tags": ["historical", "tech_detection"],
            })

        # Summary finding
        findings.append({
            "finding_type": FindingType.HISTORICAL,
            "severity": FindingSeverity.INFO,
            "value": f"URL Discovery: {len(urls)} URLs collected for {target}",
            "detail": (
                f"Total URLs (via gau): {len(urls)}. "
                f"Sensitive files: {len(unique_files)}. "
                f"Interesting endpoints: {len(unique_endpoints)}. "
                f"Unique paths: {len(set(all_paths))}."
            ),
            "mitre_technique_ids": ["T1593"],
            "fingerprint": hashlib.sha256(f"wayback:summary:{target}".encode()).hexdigest()[:32],
            "raw_data": {"total_urls": len(urls), "sensitive_files": len(unique_files), "interesting_endpoints": len(unique_endpoints)},
            "tags": ["historical", "summary"],
        })

        return findings

    # ─── gau Subprocess ────────────────────────────────────────

    async def _run_gau(self, domain: str) -> list[str]:
        """Run gau to collect URLs from multiple sources (wayback, commoncrawl, otx, urlscan)."""
        try:
            result = await self.run_command(
                ["gau", "--subs", domain],
                timeout=180,
            )
            if result["returncode"] != 0:
                logger.warning(f"gau exited with code {result['returncode']}: {result['stderr'][:200]}")

            urls: set[str] = set()
            if result["stdout"].strip():
                for line in result["stdout"].strip().split("\n"):
                    url = line.strip()
                    if url and url.startswith("http"):
                        urls.add(url)
                        if len(urls) >= URL_CAP:
                            logger.info(f"gau URL cap reached ({URL_CAP})")
                            break

            return sorted(urls)
        except Exception as e:
            logger.warning(f"gau failed: {e}")
            return []


@celery_app.task(name="app.agents.wayback.run_wayback_agent")
def run_wayback_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(WaybackAgent(scan_id, target_value, project_id, config).run())
