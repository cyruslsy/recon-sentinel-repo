"""
Recon Sentinel — Credential Leak Agent
Sources: HIBP API (Have I Been Pwned), DeHashed (if API key available)
MITRE: T1078 (Valid Accounts)
"""

import asyncio
import hashlib
import logging

import httpx

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)


class CredentialLeakAgent(BaseAgent):
    agent_type = "cred_leak"
    agent_name = "Credential Leak Agent"
    phase = ScanPhase.PASSIVE
    mitre_tags = ["T1078"]

    async def execute(self) -> list[dict]:
        domain = self.target_value
        findings = []

        # ─── Source 1: HIBP Breach Search ─────────────────────
        await self.report_progress(20, "Querying HIBP...")
        breaches = await self._query_hibp_domain(domain)

        if breaches:
            for breach in breaches:
                findings.append({
                    "finding_type": FindingType.CREDENTIAL,
                    "severity": FindingSeverity.HIGH if breach.get("has_passwords") else FindingSeverity.MEDIUM,
                    "value": f"{domain} — {breach['name']}",
                    "detail": (
                        f"Domain found in breach: {breach['name']} ({breach.get('date', 'unknown')}). "
                        f"Records: {breach.get('count', 'unknown')}. "
                        f"Data types: {', '.join(breach.get('data_classes', []))}"
                    ),
                    "mitre_technique_ids": ["T1078"],
                    "fingerprint": hashlib.sha256(f"cred:{domain}:{breach['name']}".encode()).hexdigest()[:32],
                    "raw_data": breach,
                    "tags": ["has_passwords"] if breach.get("has_passwords") else [],
                })

        await self.report_progress(70, f"Found {len(breaches)} breaches")

        # ─── Source 2: Email pattern search (passive) ─────────
        await self.report_progress(80, "Checking common email patterns...")
        common_prefixes = ["info", "admin", "support", "contact", "security", "hr", "dev"]
        for prefix in common_prefixes:
            email = f"{prefix}@{domain}"
            email_breaches = await self._query_hibp_email(email)
            if email_breaches:
                findings.append({
                    "finding_type": FindingType.CREDENTIAL,
                    "severity": FindingSeverity.MEDIUM,
                    "value": email,
                    "detail": f"Email found in {len(email_breaches)} breach(es): {', '.join(b['Name'] for b in email_breaches[:3])}",
                    "mitre_technique_ids": ["T1078"],
                    "fingerprint": hashlib.sha256(f"cred:{email}".encode()).hexdigest()[:32],
                    "raw_data": {"email": email, "breaches": email_breaches},
                })
            # HIBP free tier: 1 request per 1.5s — respect rate limit
            await asyncio.sleep(1.6)

        return findings

    async def _query_hibp_domain(self, domain: str) -> list[dict]:
        """Query HIBP for breaches affecting a domain."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breaches",
                    params={"domain": domain},
                    headers={
                        "User-Agent": "ReconSentinel/0.1",
                        "hibp-api-key": self.config.get("hibp_api_key", ""),
                    },
                )
                if resp.status_code == 200:
                    breaches = resp.json()
                    return [
                        {
                            "name": b.get("Name", ""),
                            "date": b.get("BreachDate", ""),
                            "count": b.get("PwnCount", 0),
                            "data_classes": b.get("DataClasses", []),
                            "has_passwords": "Passwords" in b.get("DataClasses", []),
                        }
                        for b in breaches
                    ]
                elif resp.status_code == 404:
                    return []  # No breaches found
                elif resp.status_code == 429:
                    logger.warning("HIBP rate limited — retry later")
                    return []
        except Exception as e:
            logger.warning(f"HIBP query failed: {e}")
        return []

    async def _query_hibp_email(self, email: str) -> list[dict]:
        """Query HIBP for a specific email."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    params={"truncateResponse": "true"},
                    headers={
                        "User-Agent": "ReconSentinel/0.1",
                        "hibp-api-key": self.config.get("hibp_api_key", ""),
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
                return []
        except Exception:
            return []


@celery_app.task(name="app.agents.cred_leak.run_cred_leak_agent")
def run_cred_leak_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    return asyncio.run(CredentialLeakAgent(scan_id, target_value, project_id, config).run())
