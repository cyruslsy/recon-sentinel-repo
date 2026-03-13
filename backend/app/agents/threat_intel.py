"""
Recon Sentinel — Threat Intelligence Agent
Sources: Shodan (host intel), VirusTotal (domain reputation)
MITRE: T1590 (Gather Victim Network Information)
"""

import hashlib
import logging

import httpx

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)


class ThreatIntelAgent(BaseAgent):
    agent_type = "threat_intel"
    agent_name = "Threat Intelligence Agent"
    phase = ScanPhase.PASSIVE
    mitre_tags = ["T1590"]

    async def execute(self) -> list[dict]:
        target = self.target_value
        findings = []

        # ─── Shodan Host Search ───────────────────────────────
        await self.report_progress(20, "Querying Shodan...")
        shodan_key = self.config.get("shodan_api_key", "")
        if shodan_key:
            shodan_data = await self._query_shodan(target, shodan_key)
            if shodan_data:
                for host in shodan_data:
                    vulns = host.get("vulns", [])
                    severity = FindingSeverity.HIGH if vulns else FindingSeverity.INFO

                    findings.append({
                        "finding_type": FindingType.THREAT_INTEL,
                        "severity": severity,
                        "value": f"Shodan: {host.get('ip', target)}:{host.get('port', 0)}",
                        "detail": (
                            f"Service: {host.get('product', 'unknown')} {host.get('version', '')}. "
                            f"OS: {host.get('os', 'unknown')}. "
                            f"Vulns: {', '.join(vulns[:5]) if vulns else 'none detected'}"
                        ),
                        "mitre_technique_ids": ["T1590"],
                        "fingerprint": hashlib.sha256(f"shodan:{host.get('ip')}:{host.get('port')}".encode()).hexdigest()[:32],
                        "raw_data": host,
                        "tags": ["known_vulns"] if vulns else [],
                    })

        # ─── VirusTotal Domain Report ─────────────────────────
        # Shodan free: 1 req/s. VT free: 4 req/min. Add delays.
        await asyncio.sleep(1.0)  # Respect Shodan rate limit before next API call
        await self.report_progress(60, "Querying VirusTotal...")
        vt_key = self.config.get("virustotal_api_key", "")
        if vt_key:
            vt_data = await self._query_virustotal(target, vt_key)
            if vt_data:
                malicious = vt_data.get("malicious_count", 0)
                severity = FindingSeverity.HIGH if malicious > 3 else FindingSeverity.MEDIUM if malicious > 0 else FindingSeverity.INFO

                findings.append({
                    "finding_type": FindingType.THREAT_INTEL,
                    "severity": severity,
                    "value": f"VirusTotal: {target}",
                    "detail": (
                        f"Reputation: {malicious} engines flagged as malicious, "
                        f"{vt_data.get('suspicious_count', 0)} suspicious. "
                        f"Categories: {', '.join(vt_data.get('categories', {}).values())[:100]}"
                    ),
                    "mitre_technique_ids": ["T1590"],
                    "fingerprint": hashlib.sha256(f"vt:{target}".encode()).hexdigest()[:32],
                    "raw_data": vt_data,
                    "tags": ["malicious_reputation"] if malicious > 0 else [],
                })

        if not shodan_key and not vt_key:
            logger.warning("No threat intel API keys configured — skipping")

        return findings

    async def _query_shodan(self, target: str, api_key: str) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://api.shodan.io/shodan/host/{target}",
                    params={"key": api_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("data", [])[:20]  # Limit to top 20 services
        except Exception as e:
            logger.warning(f"Shodan query failed: {e}")
        return []

    async def _query_virustotal(self, domain: str, api_key: str) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": api_key},
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    return {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "categories": attrs.get("categories", {}),
                        "reputation": attrs.get("reputation", 0),
                    }
        except Exception as e:
            logger.warning(f"VirusTotal query failed: {e}")
        return None


@celery_app.task(name="app.agents.threat_intel.run_threat_intel_agent")
def run_threat_intel_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(ThreatIntelAgent(scan_id, target_value, project_id, config).run())
