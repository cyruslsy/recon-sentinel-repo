"""
Recon Sentinel — JavaScript Analysis Agent
Extracts secrets, API endpoints, and keys from JS bundles of discovered web hosts.
MITRE: T1552 (Unsecured Credentials), T1190 (Exploit Public-Facing Application)

Flow:
  1. Get live web hosts from active phase findings
  2. Crawl each host for .js file URLs (from HTML source)
  3. Download JS files
  4. Regex scan for API keys, tokens, endpoints, secrets
  5. Report findings
"""

import hashlib
import logging
import re

import httpx

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.enums import FindingSeverity, FindingType, ScanPhase
from app.models.models import Finding

logger = logging.getLogger(__name__)

# Regex patterns for secrets in JavaScript
SECRET_PATTERNS = {
    "aws_access_key": {
        "regex": r"(?:AKIA)[A-Z0-9]{16}",
        "severity": FindingSeverity.CRITICAL,
        "description": "AWS Access Key ID",
    },
    "aws_secret_key": {
        "regex": r"(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "severity": FindingSeverity.CRITICAL,
        "description": "AWS Secret Access Key",
    },
    "google_api_key": {
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": FindingSeverity.HIGH,
        "description": "Google API Key",
    },
    "google_oauth": {
        "regex": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "severity": FindingSeverity.MEDIUM,
        "description": "Google OAuth Client ID",
    },
    "stripe_secret": {
        "regex": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": FindingSeverity.CRITICAL,
        "description": "Stripe Secret Key (Live)",
    },
    "stripe_publishable": {
        "regex": r"pk_live_[0-9a-zA-Z]{24,}",
        "severity": FindingSeverity.LOW,
        "description": "Stripe Publishable Key (Live)",
    },
    "slack_token": {
        "regex": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "severity": FindingSeverity.HIGH,
        "description": "Slack Token",
    },
    "github_token": {
        "regex": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "severity": FindingSeverity.CRITICAL,
        "description": "GitHub Token",
    },
    "jwt_token": {
        "regex": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": FindingSeverity.HIGH,
        "description": "JWT Token (hardcoded)",
    },
    "private_key": {
        "regex": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "severity": FindingSeverity.CRITICAL,
        "description": "Private Key",
    },
    "firebase_url": {
        "regex": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": FindingSeverity.MEDIUM,
        "description": "Firebase Database URL",
    },
    "generic_secret": {
        "regex": r"""(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['\"]""",
        "severity": FindingSeverity.MEDIUM,
        "description": "Generic API Key/Secret",
    },
}

# Regex for API endpoint extraction
ENDPOINT_PATTERNS = [
    r"""['"](/api/v[0-9]+/[a-zA-Z0-9/_\-]+)['"]""",
    r"""['"](/graphql)['"]""",
    r"""['"]https?://[^'"]+/api/[^'"]+['"]""",
    r"""fetch\(['"]([^'"]+)['"]\)""",
    r"""\.(?:get|post|put|delete|patch)\(['"]([^'"]+)['"]\)""",
]


class JSAnalysisAgent(BaseAgent):
    agent_type = "js_analysis"
    agent_name = "JavaScript Analysis Agent"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1552", "T1190"]

    async def execute(self) -> list[dict]:
        findings = []

        # ─── Phase 1: Get live hosts from active phase ────────
        await self.report_progress(5, "Getting live web hosts...")
        hosts = await self._get_live_hosts()

        if not hosts:
            # Fallback: use target directly
            target = self.target_value
            if not target.startswith("http"):
                target = f"https://{target}"
            hosts = [target]

        await self.report_progress(10, f"Analyzing JS on {len(hosts)} hosts...")

        # ─── Phase 2: Extract JS URLs from each host ──────────
        all_js_urls: set[str] = set()
        for i, host in enumerate(hosts[:20]):  # Cap at 20 hosts
            js_urls = await self._extract_js_urls(host)
            all_js_urls.update(js_urls)
            await self.report_progress(
                10 + int(30 * i / max(len(hosts[:20]), 1)),
                f"Extracted {len(all_js_urls)} JS files from {i+1} hosts",
            )

        if not all_js_urls:
            logger.info("No JS files found to analyze")
            return []

        # ─── Phase 3: Download and scan JS files ──────────────
        await self.report_progress(45, f"Scanning {len(all_js_urls)} JS files for secrets...")

        for i, js_url in enumerate(sorted(all_js_urls)[:50]):  # Cap at 50 files
            js_content = await self._download_js(js_url)
            if not js_content:
                continue

            # Scan for secrets
            secrets = self._scan_for_secrets(js_content, js_url)
            findings.extend(secrets)

            # Scan for API endpoints
            endpoints = self._extract_endpoints(js_content, js_url)
            findings.extend(endpoints)

            if i % 10 == 0:
                await self.report_progress(
                    45 + int(40 * i / max(len(all_js_urls), 1)),
                    f"Scanned {i+1}/{len(all_js_urls)} JS files, {len(findings)} findings",
                )

        return findings

    # ─── Get Live Hosts ───────────────────────────────────────

    async def _get_live_hosts(self) -> list[str]:
        """Pull live web host URLs from this scan's findings."""
        import uuid as _uuid
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.value, Finding.raw_data)
                .where(Finding.scan_id == _uuid.UUID(self.scan_id))
                .where(Finding.finding_type == FindingType.SUBDOMAIN)
            )
            hosts = []
            for value, raw_data in result.all():
                if raw_data and isinstance(raw_data, dict):
                    url = raw_data.get("url")
                    if url and url.startswith("http"):
                        hosts.append(url)
                        continue
                # Handle bare hostnames — prefix https://
                clean = value.strip()
                if clean.startswith("http"):
                    hosts.append(clean)
                elif "." in clean:
                    hosts.append(f"https://{clean}")
            return list(set(hosts))

    # ─── Extract JS URLs ─────────────────────────────────────

    async def _extract_js_urls(self, host_url: str) -> set[str]:
        """Download HTML page and extract <script src="..."> URLs."""
        js_urls = set()
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.get(host_url, headers={"User-Agent": "ReconSentinel/0.1"})
                if resp.status_code != 200:
                    return js_urls

                html = resp.text
                # Extract script src attributes
                for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                    src = match.group(1)
                    if src.endswith(".js") or ".js?" in src:
                        if src.startswith("//"):
                            src = f"https:{src}"
                        elif src.startswith("/"):
                            src = f"{host_url.rstrip('/')}{src}"
                        elif not src.startswith("http"):
                            src = f"{host_url.rstrip('/')}/{src}"
                        js_urls.add(src)
        except Exception as e:
            logger.debug(f"Failed to extract JS from {host_url}: {e}")
        return js_urls

    # ─── Download JS ──────────────────────────────────────────

    async def _download_js(self, url: str) -> str | None:
        """Download a JS file. Skip if too large (>5MB)."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers={"User-Agent": "ReconSentinel/0.1"})
                if resp.status_code == 200 and len(resp.content) < 5_000_000:
                    return resp.text
        except Exception:
            pass
        return None

    # ─── Secret Scanning ──────────────────────────────────────

    def _scan_for_secrets(self, js_content: str, source_url: str) -> list[dict]:
        """Scan JS content for hardcoded secrets."""
        findings = []
        seen = set()

        for pattern_name, config in SECRET_PATTERNS.items():
            for match in re.finditer(config["regex"], js_content):
                matched_value = match.group(0)[:80]  # Truncate for safety

                # Deduplicate
                dedup_key = f"{pattern_name}:{matched_value}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Get surrounding context (30 chars each side)
                start = max(0, match.start() - 30)
                end = min(len(js_content), match.end() + 30)
                context = js_content[start:end].replace("\n", " ").strip()

                findings.append({
                    "finding_type": FindingType.JS_SECRET,
                    "severity": config["severity"],
                    "value": f"{config['description']}: {matched_value[:40]}...",
                    "detail": f"Found in {source_url}. Context: ...{context[:100]}...",
                    "mitre_technique_ids": ["T1552"],
                    "fingerprint": hashlib.sha256(f"js:{pattern_name}:{matched_value}".encode()).hexdigest()[:32],
                    "tags": ["js_secret", pattern_name],
                    "raw_data": {
                        "source_url": source_url,
                        "pattern": pattern_name,
                        "matched_value": matched_value,
                        "context": context[:200],
                    },
                })

        return findings

    # ─── Endpoint Extraction ──────────────────────────────────

    def _extract_endpoints(self, js_content: str, source_url: str) -> list[dict]:
        """Extract API endpoints from JS content."""
        findings = []
        seen = set()

        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_content):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip("'\"")

                if endpoint in seen or len(endpoint) < 5:
                    continue
                seen.add(endpoint)

                # Only report interesting endpoints (APIs, not static assets)
                if any(skip in endpoint.lower() for skip in [".css", ".png", ".jpg", ".svg", ".woff", ".ico"]):
                    continue

                findings.append({
                    "finding_type": FindingType.JS_SECRET,
                    "severity": FindingSeverity.INFO,
                    "value": f"API endpoint: {endpoint}",
                    "detail": f"Discovered in {source_url}",
                    "mitre_technique_ids": ["T1190"],
                    "fingerprint": hashlib.sha256(f"jsapi:{endpoint}:{source_url}".encode()).hexdigest()[:32],
                    "tags": ["api_endpoint", "js_analysis"],
                    "raw_data": {"endpoint": endpoint, "source_url": source_url},
                })

        return findings


@celery_app.task(name="app.agents.js_analysis.run_js_analysis_agent")
def run_js_analysis_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(JSAnalysisAgent(scan_id, target_value, project_id, config).run())
