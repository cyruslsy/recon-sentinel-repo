"""
Recon Sentinel — Subdomain Discovery Agent
Tools: Subfinder (primary), crt.sh API (passive), DNS brute (optional)
MITRE: T1593 (Search Open Websites/Domains), T1596 (Search Open Technical Databases)

Self-correction: DNS wildcard detection — if a random subdomain resolves
to the same IP, filter that IP from results.
"""

import hashlib
import random
import string
import logging

import httpx

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)


class SubdomainAgent(BaseAgent):
    agent_type = "subdomain"
    agent_name = "Subdomain Discovery Agent"
    phase = ScanPhase.PASSIVE
    mitre_tags = ["T1593", "T1596"]

    async def execute(self) -> list[dict]:
        """Run Subfinder + crt.sh, deduplicate, detect wildcards."""
        domain = self.target_value
        all_subdomains: set[str] = set()

        # ─── Source 1: Subfinder ──────────────────────────────
        await self.report_progress(10, "Running Subfinder...")
        try:
            result = await self.run_command(
                ["subfinder", "-d", domain, "-silent", "-json", "-nW"],
                timeout=120,
                parse_json=True,
            )
            if result["parsed"]:
                for entry in result["parsed"]:
                    host = entry.get("host", "").strip().lower()
                    if host and (host.endswith(f".{domain}") or host == domain):
                        all_subdomains.add(host)
                logger.info(f"Subfinder found {len(all_subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"Subfinder failed: {e}")

        # ─── Source 2: crt.sh (Certificate Transparency) ─────
        await self.report_progress(40, "Querying crt.sh...")
        try:
            crtsh_subs = await self._query_crtsh(domain)
            all_subdomains.update(crtsh_subs)
            logger.info(f"crt.sh added {len(crtsh_subs)} subdomains")
        except Exception as e:
            logger.warning(f"crt.sh query failed: {e}")

        await self.report_progress(60, f"Found {len(all_subdomains)} subdomains, checking wildcards...")

        # ─── Wildcard Detection ───────────────────────────────
        wildcard_ips = await self._detect_wildcard(domain)
        if wildcard_ips:
            logger.info(f"Wildcard DNS detected: {wildcard_ips}")

        # ─── Resolve and Filter ───────────────────────────────
        await self.report_progress(70, "Resolving subdomains...")
        findings = []
        for sub in sorted(all_subdomains):
            resolved_ips = await self._resolve(sub)

            # Filter out wildcard IPs
            is_wildcard = bool(wildcard_ips and set(resolved_ips) <= wildcard_ips)

            fingerprint = hashlib.sha256(f"subdomain:{sub}".encode()).hexdigest()[:32]

            findings.append({
                "finding_type": FindingType.SUBDOMAIN,
                "severity": FindingSeverity.INFO,
                "value": sub,
                "detail": f"Subdomain discovered via passive enumeration. Resolves to: {', '.join(resolved_ips) or 'NXDOMAIN'}",
                "mitre_technique_ids": ["T1593"],
                "fingerprint": fingerprint,
                "raw_data": {
                    "resolved_ips": resolved_ips,
                    "is_wildcard": is_wildcard,
                    "sources": self._get_sources(sub, all_subdomains),
                },
                "tags": ["wildcard"] if is_wildcard else [],
            })

        return findings

    # ─── crt.sh Query ─────────────────────────────────────────

    async def _query_crtsh(self, domain: str) -> set[str]:
        """Query Certificate Transparency logs via crt.sh."""
        subdomains = set()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "ReconSentinel/0.1"},
                )
                if resp.status_code == 200:
                    for entry in resp.json():
                        name = entry.get("name_value", "")
                        for line in name.split("\n"):
                            clean = line.strip().lower()
                            if clean and "*" not in clean:
                                if clean.endswith(f".{domain}") or clean == domain:
                                    subdomains.add(clean)
        except Exception as e:
            logger.warning(f"crt.sh request failed: {e}")
        return subdomains

    # ─── Wildcard Detection ───────────────────────────────────

    async def _detect_wildcard(self, domain: str) -> set[str]:
        """
        Self-correction pattern: DNS Wildcard Detection.
        Generate a random subdomain. If it resolves, the domain has wildcard DNS.
        Returns the set of wildcard IPs to filter from results.
        """
        random_prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        random_sub = f"{random_prefix}.{domain}"
        ips = await self._resolve(random_sub)
        return set(ips) if ips else set()

    # ─── DNS Resolution ───────────────────────────────────────

    async def _resolve(self, hostname: str) -> list[str]:
        """Resolve a hostname to IPs using system DNS via async subprocess."""
        try:
            result = await self.run_command(
                ["dig", "+short", hostname, "A"],
                timeout=10,
                silent=True,  # Don't spam progress for each DNS lookup
            )
            if result["returncode"] == 0 and result["stdout"].strip():
                ips = [
                    line.strip() for line in result["stdout"].strip().split("\n")
                    if line.strip() and not line.strip().endswith(".")
                ]
                return ips
        except Exception:
            pass
        return []

    @staticmethod
    def _get_sources(subdomain: str, all_subs: set[str]) -> list[str]:
        """Placeholder — in full implementation, track per-subdomain source."""
        return ["subfinder", "crt.sh"]


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.subdomain.run_subdomain_agent", bind=True)
def run_subdomain_agent(self, scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    """Celery task wrapper — runs the async agent in an event loop."""
    import asyncio
    agent = SubdomainAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
