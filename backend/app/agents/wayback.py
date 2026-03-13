"""
Recon Sentinel — Wayback Machine Agent
Queries the Wayback Machine CDX API to discover:
  - Historical URLs (old endpoints, removed pages)
  - Leaked API keys and config files in archived pages
  - Admin panels and login pages that were removed but still cached
  - Old JavaScript files with embedded secrets

Phase: Passive
MITRE: T1593 (Search Open Websites/Domains)
"""

import hashlib
import logging
from collections import Counter
from urllib.parse import urlparse

import httpx

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

class WaybackAgent(BaseAgent):
    agent_type = "wayback"
    agent_name = "Wayback Machine Discovery"
    mitre_tags = ["T1593"]
    max_retries = 1

    async def execute(self) -> list[dict]:
        target = self.target_value
        findings = []

        # ─── Phase 1: Query CDX API for all archived URLs ─────
        await self.report_progress(10, "Querying Wayback Machine CDX API...")
        urls = await self._query_cdx(target)

        if not urls:
            logger.info(f"No Wayback Machine data for {target}")
            return findings

        await self.report_progress(30, f"Found {len(urls)} archived URLs")

        # ─── Phase 2: Classify interesting URLs ───────────────
        await self.report_progress(40, "Classifying URLs...")
        interesting_files = []
        interesting_endpoints = []
        all_paths = []

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            all_paths.append(path)

            # Check for sensitive file extensions
            for ext in INTERESTING_EXTENSIONS:
                if path.endswith(ext):
                    interesting_files.append(url)
                    break

            # Check for interesting paths
            for pattern in INTERESTING_PATHS:
                if pattern in path:
                    interesting_endpoints.append(url)
                    break

        # Deduplicate by path (keep unique paths, not timestamps)
        seen_paths = set()
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

        for url in unique_files[:50]:  # Cap at 50
            path = urlparse(url).path
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
            severity = FindingSeverity.HIGH if ext in {".env", ".key", ".pem", ".htpasswd", ".sql", ".bak"} else FindingSeverity.MEDIUM

            findings.append({
                "finding_type": FindingType.HISTORICAL,
                "severity": severity,
                "value": f"Archived sensitive file: {path}",
                "detail": f"Found in Wayback Machine: {url}. File type '{ext}' may contain credentials, configuration, or backup data.",
                "mitre_technique_ids": ["T1593"],
                "fingerprint": hashlib.sha256(f"wayback:file:{path}".encode()).hexdigest()[:32],
                "raw_data": {"url": url, "path": path, "extension": ext, "source": "wayback_cdx"},
                "tags": ["historical", "sensitive_file"],
            })

        for url in unique_endpoints[:50]:  # Cap at 50
            path = urlparse(url).path
            severity = FindingSeverity.MEDIUM if any(p in path for p in {"/admin", "/debug", "/actuator", "/.git/"}) else FindingSeverity.INFO

            findings.append({
                "finding_type": FindingType.HISTORICAL,
                "severity": severity,
                "value": f"Archived endpoint: {path}",
                "detail": f"Found in Wayback Machine: {url}. Endpoint may still be accessible or reveal architecture information.",
                "mitre_technique_ids": ["T1593"],
                "fingerprint": hashlib.sha256(f"wayback:endpoint:{path}".encode()).hexdigest()[:32],
                "raw_data": {"url": url, "path": path, "source": "wayback_cdx"},
                "tags": ["historical", "endpoint"],
            })

        # ─── Phase 4: URL pattern analysis ────────────────────
        await self.report_progress(80, "Analyzing URL patterns...")

        # Find technology indicators from URL patterns
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
                "detail": f"URL pattern analysis across {len(urls)} archived URLs suggests: {', '.join(f'{t[0]} ({t[1]} URLs)' for t in top_tech)}",
                "mitre_technique_ids": ["T1592"],
                "fingerprint": hashlib.sha256(f"wayback:tech:{target}".encode()).hexdigest()[:32],
                "raw_data": {"tech_indicators": dict(tech_indicators), "total_urls": len(urls)},
                "tags": ["historical", "tech_detection"],
            })

        # Summary finding
        findings.append({
            "finding_type": FindingType.HISTORICAL,
            "severity": FindingSeverity.INFO,
            "value": f"Wayback Machine: {len(urls)} URLs archived for {target}",
            "detail": (
                f"Total archived URLs: {len(urls)}. "
                f"Sensitive files: {len(unique_files)}. "
                f"Interesting endpoints: {len(unique_endpoints)}. "
                f"Unique paths: {len(set(all_paths))}."
            ),
            "mitre_technique_ids": ["T1593"],
            "fingerprint": hashlib.sha256(f"wayback:summary:{target}".encode()).hexdigest()[:32],
            "raw_data": {"total_urls": len(urls), "sensitive_files": len(unique_files), "interesting_endpoints": len(unique_endpoints)},
            "tags": ["historical", "summary"],
        })

        await self.report_progress(100, f"Wayback analysis complete: {len(findings)} findings")
        return findings

    # ─── CDX API ──────────────────────────────────────────────

    async def _query_cdx(self, domain: str, max_pages: int = 5) -> list[str]:
        """Query Wayback Machine CDX API for archived URLs."""
        all_urls = set()

        async with httpx.AsyncClient(timeout=30) as client:
            for page in range(max_pages):
                try:
                    resp = await client.get(
                        "https://web.archive.org/cdx/search/cdx",
                        params={
                            "url": f"*.{domain}/*",
                            "output": "text",
                            "fl": "original",
                            "collapse": "urlkey",
                            "page": page,
                            "limit": 10000,
                        },
                    )
                    if resp.status_code != 200:
                        break
                    lines = resp.text.strip().split("\n")
                    if not lines or lines == [""]:
                        break
                    for line in lines:
                        url = line.strip()
                        if url and url.startswith("http"):
                            all_urls.add(url)

                    await self.report_progress(
                        10 + (page * 4),
                        f"CDX page {page + 1}: {len(all_urls)} URLs",
                    )

                except httpx.RequestError as e:
                    logger.warning(f"CDX API error on page {page}: {e}")
                    break

        return sorted(all_urls)


@celery_app.task(name="app.agents.wayback.run_wayback_agent")
def run_wayback_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(WaybackAgent(scan_id, target_value, project_id, config).run())
