"""
Recon Sentinel — OSINT Agent
Tool: theHarvester (email, host, and name discovery)
MITRE: T1589 (Gather Victim Identity Information), T1593 (Search Open Websites)
"""

import hashlib
import logging

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)


class OSINTAgent(BaseAgent):
    agent_type = "osint"
    agent_name = "OSINT Discovery Agent"
    phase = ScanPhase.PASSIVE
    mitre_tags = ["T1589", "T1593"]

    async def execute(self) -> list[dict]:
        domain = self.target_value
        findings = []

        await self.report_progress(10, "Running theHarvester...")

        sources = self.config.get("sources", "google,bing,linkedin,dnsdumpster,crtsh")

        try:
            result = await self.run_command([
                "theHarvester",
                "-d", domain,
                "-b", sources,
                "-f", "/tmp/harvester_output",
                "-l", "200",
            ], timeout=180)

            output = result["stdout"]

            # Parse emails
            emails = self._extract_section(output, "Emails found:", "Hosts found:")
            for email in emails:
                findings.append({
                    "finding_type": FindingType.OSINT,
                    "severity": FindingSeverity.INFO,
                    "value": email,
                    "detail": f"Email address discovered via OSINT: {email}",
                    "mitre_technique_ids": ["T1589"],
                    "fingerprint": hashlib.sha256(f"osint:email:{email}".encode()).hexdigest()[:32],
                    "tags": ["email"],
                })

            # Parse hosts
            hosts = self._extract_section(output, "Hosts found:", "Virtual IPs:")
            for host in hosts:
                findings.append({
                    "finding_type": FindingType.OSINT,
                    "severity": FindingSeverity.INFO,
                    "value": host,
                    "detail": f"Host discovered via OSINT: {host}",
                    "mitre_technique_ids": ["T1593"],
                    "fingerprint": hashlib.sha256(f"osint:host:{host}".encode()).hexdigest()[:32],
                    "tags": ["host"],
                })

        except Exception as e:
            logger.warning(f"theHarvester failed: {e}")

        await self.report_progress(90, f"Found {len(findings)} OSINT items")
        return findings

    @staticmethod
    def _extract_section(output: str, start_marker: str, end_marker: str) -> list[str]:
        """Extract items between two section markers in theHarvester output."""
        items = []
        in_section = False
        for line in output.split("\n"):
            stripped = line.strip()
            if start_marker.lower() in stripped.lower():
                in_section = True
                continue
            if end_marker.lower() in stripped.lower():
                break
            if in_section and stripped and not stripped.startswith("[") and not stripped.startswith("-"):
                items.append(stripped)
        return items


@celery_app.task(name="app.agents.osint.run_osint_agent", bind=True)
def run_osint_agent(self, scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(OSINTAgent(scan_id, target_value, project_id, config).run())
