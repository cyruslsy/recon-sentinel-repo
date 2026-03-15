"""
Recon Sentinel — Web Spider Agent (katana)
Crawls live web hosts discovered by web_recon to find URLs, API endpoints,
and hidden paths via JavaScript-aware crawling.

Phase: Active (runs after web_recon in per-target fan-out)
MITRE: T1592 (Gather Victim Host Information)
"""

import hashlib
import logging
import uuid
from urllib.parse import urlparse

from sqlalchemy import select

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.enums import FindingType, FindingSeverity, ScanPhase
from app.models.models import Finding

logger = logging.getLogger(__name__)

URL_CAP = 5000


class WebSpiderAgent(BaseAgent):
    agent_type = "web_spider"
    agent_name = "Web Spider Agent (katana)"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1592"]
    max_retries = 1

    async def execute(self) -> list[dict]:
        target = self.target_value
        findings = []

        # Build target URL — use HTTPS first, fall back to HTTP
        target_url = f"https://{target}" if not target.startswith("http") else target

        await self.report_progress(10, "Running katana web crawler...")
        crawled_urls = await self._run_katana(target_url)

        if not crawled_urls:
            logger.info(f"katana found no URLs for {target}")
            return findings

        await self.report_progress(60, f"Processing {len(crawled_urls)} crawled URLs...")

        # Classify and create findings
        seen_paths: set[str] = set()
        for entry in crawled_urls:
            url = entry.get("url", "") if isinstance(entry, dict) else str(entry)
            if not url:
                continue

            parsed = urlparse(url)
            path = parsed.path.lower()

            # Deduplicate by path
            if path in seen_paths:
                continue
            seen_paths.add(path)

            finding_type, severity, tags = self._classify_url(url, path)

            fingerprint = hashlib.sha256(f"spider:{target}:{path}".encode()).hexdigest()[:32]

            raw_data: dict = {"url": url, "source": "katana"}
            if isinstance(entry, dict):
                raw_data["status_code"] = entry.get("status-code")
                raw_data["content_type"] = entry.get("content-type")
                raw_data["method"] = entry.get("method", "GET")

            findings.append({
                "finding_type": finding_type,
                "severity": severity,
                "value": url,
                "detail": f"URL discovered via web crawling (katana depth=3). Path: {path}",
                "mitre_technique_ids": ["T1592"],
                "fingerprint": fingerprint,
                "raw_data": raw_data,
                "tags": ["crawled"] + tags,
            })

        logger.info(f"katana produced {len(findings)} findings for {target}")
        return findings

    async def _run_katana(self, target_url: str) -> list[dict]:
        """Run katana with JS crawling and JSON output."""
        try:
            result = await self.run_command(
                [
                    "katana",
                    "-u", target_url,
                    "-d", "3",           # depth
                    "-jc",               # JS crawling
                    "-kf", "all",        # known file detection
                    "-json",             # structured output
                    "-silent",
                    "-timeout", "10",
                    "-no-color",
                ],
                timeout=300,
                parse_json=True,
            )

            if result["parsed"]:
                urls = result["parsed"][:URL_CAP]
                return urls

            # Fall back to line-by-line if JSON parsing failed
            if result["stdout"].strip():
                lines = result["stdout"].strip().split("\n")
                return [{"url": line.strip()} for line in lines if line.strip().startswith("http")][:URL_CAP]

            return []
        except Exception as e:
            logger.warning(f"katana failed for {target_url}: {e}")
            return []

    @staticmethod
    def _classify_url(url: str, path: str) -> tuple[FindingType, FindingSeverity, list[str]]:
        """Classify a URL by type and severity."""
        tags: list[str] = []

        # API endpoints
        if "/api/" in path or "/graphql" in path or "/swagger" in path or "/openapi" in path:
            return FindingType.API_ENDPOINT, FindingSeverity.INFO, ["api"]

        # Sensitive paths
        sensitive = {"/admin", "/debug", "/actuator", "/.git/", "/.env", "/phpinfo", "/server-status"}
        if any(s in path for s in sensitive):
            return FindingType.DIRECTORY, FindingSeverity.MEDIUM, ["sensitive"]

        # JS files
        if path.endswith(".js") or path.endswith(".js.map"):
            tags.append("javascript")
            if ".map" in path:
                return FindingType.JS_SECRET, FindingSeverity.LOW, tags
            return FindingType.DIRECTORY, FindingSeverity.INFO, tags

        # Config/backup files
        config_exts = {".env", ".yml", ".yaml", ".json", ".xml", ".conf", ".bak", ".sql", ".log"}
        for ext in config_exts:
            if path.endswith(ext):
                return FindingType.DIRECTORY, FindingSeverity.MEDIUM, ["config"]

        # Default: general URL discovery
        return FindingType.DIRECTORY, FindingSeverity.INFO, []


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.web_spider.run_web_spider_agent")
def run_web_spider_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    """Celery task wrapper — runs the async agent in an event loop."""
    import asyncio
    agent = WebSpiderAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
