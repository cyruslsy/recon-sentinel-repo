"""
Recon Sentinel — Subdomain Takeover Agent
Checks all discovered subdomains for dangling CNAME records that point
to deprovisioned cloud services (takeover candidates).
MITRE: T1584 (Compromise Infrastructure)

Uses the can-i-take-over-xyz fingerprint database approach:
  1. Resolve subdomain CNAMEs
  2. Match CNAME against known vulnerable services
  3. HTTP probe for takeover fingerprint strings in response body
  4. Report confirmed/possible takeovers
"""

import hashlib
import logging
import warnings

import httpx
import urllib3

# Suppress SSL warnings for takeover probes (targets often have invalid/expired certs)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.enums import FindingSeverity, FindingType, ScanPhase
from app.models.models import Finding

logger = logging.getLogger(__name__)

# Takeover fingerprints: CNAME pattern → (service, response fingerprint, severity)
# Based on https://github.com/EdOverflow/can-i-take-over-xyz
TAKEOVER_FINGERPRINTS = {
    ".s3.amazonaws.com": {
        "service": "AWS S3",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": FindingSeverity.CRITICAL,
    },
    ".herokuapp.com": {
        "service": "Heroku",
        "fingerprints": ["No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app"],
        "severity": FindingSeverity.HIGH,
    },
    ".ghost.io": {
        "service": "Ghost",
        "fingerprints": ["The thing you were looking for is no longer here"],
        "severity": FindingSeverity.HIGH,
    },
    "pantheon.io": {
        "service": "Pantheon",
        "fingerprints": ["404 error unknown site", "The gods have abandoned this site"],
        "severity": FindingSeverity.HIGH,
    },
    ".netlify.app": {
        "service": "Netlify",
        "fingerprints": ["Not Found - Request ID"],
        "severity": FindingSeverity.HIGH,
    },
    ".netlify.com": {
        "service": "Netlify",
        "fingerprints": ["Not Found - Request ID"],
        "severity": FindingSeverity.HIGH,
    },
    ".azurewebsites.net": {
        "service": "Azure App Service",
        "fingerprints": ["404 Web Site not found", "Azure Web App - Your web app is running"],
        "severity": FindingSeverity.HIGH,
    },
    ".cloudapp.azure.com": {
        "service": "Azure VM",
        "fingerprints": [],  # Check NXDOMAIN on the CNAME target
        "severity": FindingSeverity.HIGH,
    },
    ".trafficmanager.net": {
        "service": "Azure Traffic Manager",
        "fingerprints": [],
        "severity": FindingSeverity.HIGH,
    },
    "github.io": {
        "service": "GitHub Pages",
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"],
        "severity": FindingSeverity.HIGH,
    },
    ".vercel.app": {
        "service": "Vercel",
        "fingerprints": ["The deployment could not be found"],
        "severity": FindingSeverity.HIGH,
    },
    ".surge.sh": {
        "service": "Surge.sh",
        "fingerprints": ["project not found"],
        "severity": FindingSeverity.HIGH,
    },
    ".fly.dev": {
        "service": "Fly.io",
        "fingerprints": ["404 Not Found"],
        "severity": FindingSeverity.MEDIUM,
    },
    ".webflow.io": {
        "service": "Webflow",
        "fingerprints": ["The page you are looking for doesn't exist"],
        "severity": FindingSeverity.HIGH,
    },
    ".zendesk.com": {
        "service": "Zendesk",
        "fingerprints": ["Help Center Closed"],
        "severity": FindingSeverity.HIGH,
    },
    ".shopify.com": {
        "service": "Shopify",
        "fingerprints": ["Sorry, this shop is currently unavailable"],
        "severity": FindingSeverity.HIGH,
    },
    ".tumblr.com": {
        "service": "Tumblr",
        "fingerprints": ["There's nothing here", "Whatever you were looking for"],
        "severity": FindingSeverity.MEDIUM,
    },
    ".wordpress.com": {
        "service": "WordPress.com",
        "fingerprints": ["Do you want to register"],
        "severity": FindingSeverity.MEDIUM,
    },
    ".cargocollective.com": {
        "service": "Cargo Collective",
        "fingerprints": ["404 Not Found"],
        "severity": FindingSeverity.MEDIUM,
    },
    ".firebaseapp.com": {
        "service": "Firebase",
        "fingerprints": ["Firebase Hosting Setup Complete", "Site Not Found"],
        "severity": FindingSeverity.HIGH,
    },
    ".appspot.com": {
        "service": "Google App Engine",
        "fingerprints": ["Error: Not Found", "The requested URL was not found"],
        "severity": FindingSeverity.HIGH,
    },
}


class SubdomainTakeoverAgent(BaseAgent):
    agent_type = "subdomain_takeover"
    agent_name = "Subdomain Takeover Agent"
    phase = ScanPhase.VULN
    mitre_tags = ["T1584"]

    async def execute(self) -> list[dict]:
        findings = []

        # ─── Phase 1: Get all discovered subdomains ───────────
        await self.report_progress(5, "Loading discovered subdomains...")
        import uuid
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.value)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
                .where(Finding.finding_type == FindingType.SUBDOMAIN)
            )
            subdomains = list(set(r[0] for r in result.all()))

        # Add base domain
        if self.target_value not in subdomains:
            subdomains.append(self.target_value)

        if not subdomains:
            return []

        await self.report_progress(10, f"Checking {len(subdomains)} subdomains for takeover...")

        # ─── Phase 2: Check each subdomain ────────────────────
        for i, sub in enumerate(subdomains[:100]):  # Cap at 100
            # Clean up subdomain (remove protocol if present)
            clean_sub = sub.replace("https://", "").replace("http://", "").rstrip("/")

            result = await self._check_takeover(clean_sub)
            if result:
                findings.append(result)

            if i % 10 == 0:
                await self.report_progress(
                    10 + int(80 * i / max(len(subdomains[:100]), 1)),
                    f"Checked {i+1}/{len(subdomains[:100])} — {len(findings)} takeover candidates",
                )

        return findings

    async def _check_takeover(self, subdomain: str) -> dict | None:
        """Check a single subdomain for takeover vulnerability."""

        # Step 1: Get CNAME
        cname = await self._get_cname(subdomain)
        if not cname:
            return None  # No CNAME — not a takeover candidate

        # Step 2: Match CNAME against known vulnerable services
        matched_service = None
        for pattern, config in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname.lower():
                matched_service = config
                break

        if not matched_service:
            return None  # CNAME doesn't match any known service

        # Step 3: Check if CNAME target is dangling (NXDOMAIN)
        cname_resolves = await self._resolves(cname)

        # Step 4: HTTP probe for fingerprint strings
        fingerprint_matched = False
        matched_fingerprint = ""
        if matched_service["fingerprints"]:
            fingerprint_matched, matched_fingerprint = await self._probe_fingerprint(
                subdomain, matched_service["fingerprints"]
            )

        # Determine finding
        if fingerprint_matched:
            # Confirmed takeover — fingerprint matched
            return {
                "finding_type": FindingType.VULNERABILITY,
                "severity": matched_service["severity"],
                "value": f"TAKEOVER: {subdomain} → {matched_service['service']}",
                "detail": (
                    f"Subdomain takeover confirmed. {subdomain} has CNAME to {cname} "
                    f"({matched_service['service']}) and response contains takeover fingerprint: "
                    f"'{matched_fingerprint[:60]}'"
                ),
                "mitre_technique_ids": ["T1584"],
                "fingerprint": hashlib.sha256(f"takeover:{subdomain}:{cname}".encode()).hexdigest()[:32],
                "tags": ["subdomain_takeover", "confirmed", matched_service["service"].lower().replace(" ", "_")],
                "raw_data": {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": matched_service["service"],
                    "fingerprint_match": matched_fingerprint[:100],
                    "cname_resolves": cname_resolves,
                    "confirmed": True,
                },
            }
        elif not cname_resolves:
            # Probable takeover — CNAME dangling (NXDOMAIN)
            return {
                "finding_type": FindingType.VULNERABILITY,
                "severity": FindingSeverity.HIGH,
                "value": f"POSSIBLE TAKEOVER: {subdomain} → {matched_service['service']}",
                "detail": (
                    f"Probable subdomain takeover. {subdomain} has CNAME to {cname} "
                    f"({matched_service['service']}) but CNAME target does not resolve (NXDOMAIN). "
                    f"The cloud resource may have been deprovisioned."
                ),
                "mitre_technique_ids": ["T1584"],
                "fingerprint": hashlib.sha256(f"takeover:{subdomain}:{cname}".encode()).hexdigest()[:32],
                "tags": ["subdomain_takeover", "probable", matched_service["service"].lower().replace(" ", "_")],
                "raw_data": {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": matched_service["service"],
                    "cname_resolves": False,
                    "confirmed": False,
                },
            }

        return None  # CNAME matches a service but it's active — not takeover-able

    async def _get_cname(self, hostname: str) -> str | None:
        from app.agents.dns_utils import get_cname
        return await get_cname(self, hostname)

    async def _resolves(self, hostname: str) -> bool:
        from app.agents.dns_utils import resolves
        return await resolves(self, hostname)

    async def _probe_fingerprint(self, subdomain: str, fingerprints: list[str]) -> tuple[bool, str]:
        """HTTP GET the subdomain and check for takeover fingerprint strings."""
        for scheme in ["https", "http"]:
            try:
                async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                    resp = await client.get(f"{scheme}://{subdomain}")
                    body = resp.text[:10000]  # Only check first 10KB
                    for fp in fingerprints:
                        if fp.lower() in body.lower():
                            return True, fp
            except Exception:
                continue
        return False, ""


@celery_app.task(name="app.agents.subdomain_takeover.run_subdomain_takeover_agent")
def run_subdomain_takeover_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(SubdomainTakeoverAgent(scan_id, target_value, project_id, config).run())
