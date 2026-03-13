"""
Recon Sentinel — Web Reconnaissance Agent
Tools: httpx (HTTP probing), GoWitness (screenshots), header-based tech detection
MITRE: T1592 (Gather Victim Host Information)

Takes subdomains from the passive phase and probes them for:
  - HTTP status, title, content-length
  - Technology detection via response headers
  - Screenshots of live web pages
"""

import hashlib
import logging
import os

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)

# Common tech signatures in response headers
TECH_SIGNATURES = {
    "server": {
        "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
        "microsoft-iis": "IIS", "gunicorn": "Gunicorn", "openresty": "OpenResty",
        "litespeed": "LiteSpeed", "caddy": "Caddy", "envoy": "Envoy",
    },
    "x-powered-by": {
        "php": "PHP", "asp.net": "ASP.NET", "express": "Express.js",
        "next.js": "Next.js", "nuxt": "Nuxt.js", "django": "Django",
        "rails": "Ruby on Rails", "flask": "Flask", "laravel": "Laravel",
    },
    "x-generator": {
        "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
        "ghost": "Ghost", "hugo": "Hugo", "gatsby": "Gatsby",
    },
}


class WebReconAgent(BaseAgent):
    agent_type = "web_recon"
    agent_name = "Web Reconnaissance Agent"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1592"]

    async def execute(self) -> list[dict]:
        """Run httpx to probe live hosts, detect tech, take screenshots."""
        target = self.target_value
        findings = []

        # ─── Phase 1: HTTP Probing (httpx) ────────────────────
        await self.report_progress(10, "Running httpx...")
        probed = await self._run_httpx(target)

        if not probed:
            logger.info(f"httpx found 0 live hosts for {target}")
            return []

        await self.report_progress(50, f"Probed {len(probed)} live hosts")

        # ─── Phase 2: Screenshots (GoWitness) ────────────────
        await self.report_progress(55, "Taking screenshots...")
        screenshots = await self._run_gowitness(probed)

        # ─── Phase 3: Build Findings ──────────────────────────
        await self.report_progress(75, "Building findings...")

        for host_data in probed:
            url = host_data.get("url", "")
            status_code = host_data.get("status_code", 0)
            title = host_data.get("title", "")
            tech_detected = host_data.get("tech", [])
            content_length = host_data.get("content_length", 0)

            # Determine severity
            severity = FindingSeverity.INFO
            tags = []

            if self._has_login_panel(title, url):
                severity = FindingSeverity.MEDIUM
                tags.append("login_panel")

            if self._has_sensitive_headers(host_data.get("headers", {})):
                tags.append("sensitive_headers")

            fingerprint = hashlib.sha256(f"webrecon:{url}".encode()).hexdigest()[:32]
            screenshot_path = screenshots.get(url)

            findings.append({
                "finding_type": FindingType.SUBDOMAIN,
                "severity": severity,
                "value": url,
                "detail": (
                    f"Live host: HTTP {status_code} | Title: {title or '(none)'} | "
                    f"Tech: {', '.join(tech_detected) or 'unknown'} | "
                    f"Size: {content_length} bytes"
                ),
                "mitre_technique_ids": ["T1592"],
                "fingerprint": fingerprint,
                "tags": tags,
                "raw_data": {
                    "url": url,
                    "status_code": status_code,
                    "title": title,
                    "content_length": content_length,
                    "tech_detected": tech_detected,
                    "has_login": "login_panel" in tags,
                    "screenshot_path": screenshot_path,
                    "headers": host_data.get("headers", {}),
                },
            })

        return findings

    # ─── httpx Probing ────────────────────────────────────────

    async def _run_httpx(self, target: str) -> list[dict]:
        """Probe target for live HTTP services using httpx."""
        from app.agents.evasion import random_ua
        cmd = [
            "httpx",
            "-u", target,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-content-length",
            "-tech-detect",
            "-follow-redirects",
            "-timeout", "10",
            "-retries", "1",
            "-H", f"User-Agent: {random_ua()}",
        ]

        try:
            result = await self.run_command(cmd, timeout=120, parse_json=True)
            hosts = []
            if result["parsed"]:
                for entry in result["parsed"]:
                    host_data = {
                        "url": entry.get("url", ""),
                        "status_code": entry.get("status_code", 0),
                        "title": entry.get("title", ""),
                        "content_length": entry.get("content_length", 0),
                        "tech": entry.get("tech", []),
                        "headers": entry.get("header", {}),
                    }

                    # Supplement tech detection from headers
                    header_tech = self._detect_tech_from_headers(host_data["headers"])
                    host_data["tech"] = list(set(host_data["tech"] + header_tech))

                    hosts.append(host_data)
            return hosts
        except Exception as e:
            logger.warning(f"httpx failed: {e}")
            return []

    # ─── GoWitness Screenshots ────────────────────────────────

    async def _run_gowitness(self, probed_hosts: list[dict]) -> dict[str, str]:
        """Take screenshots of live hosts using GoWitness."""
        screenshots = {}
        output_dir = f"/data/screenshots/{self.scan_id}"

        # Create output directory
        await self.run_command(["mkdir", "-p", output_dir], timeout=5)

        for i, host in enumerate(probed_hosts):
            url = host.get("url", "")
            if not url:
                continue

            # Generate safe filename
            safe_name = hashlib.md5(url.encode()).hexdigest()[:12]
            output_path = f"{output_dir}/{safe_name}.png"

            try:
                await self.run_command(
                    [
                        "gowitness", "single",
                        "--url", url,
                        "--screenshot-path", output_dir,
                        "--disable-logging",
                        "--timeout", "15",
                    ],
                    timeout=30,
                )

                # Check if screenshot was created
                check = await self.run_command(["ls", output_dir], timeout=5)
                if safe_name in check.get("stdout", ""):
                    screenshots[url] = output_path

            except Exception as e:
                logger.debug(f"GoWitness failed for {url}: {e}")

            if i % 5 == 0:
                await self.report_progress(
                    55 + int(20 * i / max(len(probed_hosts), 1)),
                    f"Screenshots: {i}/{len(probed_hosts)}",
                )

        return screenshots

    # ─── Tech Detection ───────────────────────────────────────

    @staticmethod
    def _detect_tech_from_headers(headers: dict) -> list[str]:
        """Detect technologies from HTTP response headers."""
        detected = []
        for header_name, signatures in TECH_SIGNATURES.items():
            # httpx returns headers as lists or strings
            values = headers.get(header_name, [])
            if isinstance(values, str):
                values = [values]
            for val in values:
                val_lower = val.lower()
                for keyword, tech_name in signatures.items():
                    if keyword in val_lower:
                        detected.append(tech_name)
        return detected

    @staticmethod
    def _has_login_panel(title: str, url: str) -> bool:
        """Detect login panels from page title and URL."""
        login_keywords = {"login", "sign in", "signin", "log in", "admin", "auth", "sso", "dashboard"}
        text = f"{title} {url}".lower()
        return any(kw in text for kw in login_keywords)

    @staticmethod
    def _has_sensitive_headers(headers: dict) -> bool:
        """Detect sensitive or debug headers that shouldn't be exposed."""
        sensitive = {"x-debug", "x-debug-token", "x-aspnet-version", "x-powered-by", "server-timing"}
        return any(h.lower() in sensitive for h in headers)


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.web_recon.run_web_recon_agent")
def run_web_recon_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    agent = WebReconAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
