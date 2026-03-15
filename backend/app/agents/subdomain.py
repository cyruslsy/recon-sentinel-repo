"""
Recon Sentinel — Subdomain Discovery Agent
Tools: Subfinder (passive), crt.sh (passive), puredns+massdns (active brute-force)
MITRE: T1593 (Search Open Websites/Domains), T1596 (Search Open Technical Databases)

Phase B upgrades:
  - puredns brute-force with n0kovo 3M wordlist (full/bounty profiles)
  - SecLists 5K wordlist for quick/stealth profiles
  - Subdomain permutation via puredns resolve
  - Wildcard detection filters false positives
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
        """Run Subfinder + crt.sh (passive) + puredns brute-force (active), deduplicate, detect wildcards."""
        domain = self.target_value
        profile = self.config.get("profile", "full")
        all_subdomains: set[str] = set()
        sources: dict[str, set[str]] = {}  # subdomain → set of source names

        def _track(sub: str, source: str) -> None:
            sources.setdefault(sub, set()).add(source)

        # ─── Source 1: Subfinder (passive) ────────────────────
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
                        _track(host, "subfinder")
                logger.info(f"Subfinder found {len(all_subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"Subfinder failed: {e}")

        # ─── Source 2: crt.sh (Certificate Transparency) ─────
        await self.report_progress(25, "Querying crt.sh...")
        try:
            crtsh_subs = await self._query_crtsh(domain)
            for s in crtsh_subs:
                _track(s, "crt.sh")
            all_subdomains.update(crtsh_subs)
            logger.info(f"crt.sh added {len(crtsh_subs)} subdomains")
        except Exception as e:
            logger.warning(f"crt.sh query failed: {e}")

        # ─── Source 3: puredns brute-force (active) ───────────
        # Skip for passive_only profile; use small wordlist for quick/stealth
        if profile != "passive_only":
            brute_subs = await self._run_puredns_bruteforce(domain, profile)
            for s in brute_subs:
                _track(s, "puredns")
            before = len(all_subdomains)
            all_subdomains.update(brute_subs)
            logger.info(f"puredns brute-force added {len(all_subdomains) - before} new subdomains")

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
            is_wildcard = bool(wildcard_ips and set(resolved_ips) <= wildcard_ips)
            sub_sources = sorted(sources.get(sub, ["unknown"]))

            fingerprint = hashlib.sha256(f"subdomain:{sub}".encode()).hexdigest()[:32]

            findings.append({
                "finding_type": FindingType.SUBDOMAIN,
                "severity": FindingSeverity.INFO,
                "value": sub,
                "detail": f"Subdomain discovered via {', '.join(sub_sources)}. Resolves to: {', '.join(resolved_ips) or 'NXDOMAIN'}",
                "mitre_technique_ids": ["T1593"],
                "fingerprint": fingerprint,
                "raw_data": {
                    "resolved_ips": resolved_ips,
                    "is_wildcard": is_wildcard,
                    "sources": sub_sources,
                },
                "tags": ["wildcard"] if is_wildcard else [],
            })

        return findings

    # ─── puredns Brute-Force ──────────────────────────────────

    WORDLISTS = {
        "quick": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "stealth": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "full": "/usr/share/wordlists/n0kovo_subdomains_huge.txt",
        "bounty": "/usr/share/wordlists/n0kovo_subdomains_huge.txt",
    }
    RESOLVERS = "/usr/share/wordlists/resolvers.txt"

    async def _run_puredns_bruteforce(self, domain: str, profile: str) -> set[str]:
        """Run puredns brute-force with profile-appropriate wordlist."""
        wordlist = self.WORDLISTS.get(profile, self.WORDLISTS["quick"])

        import os
        if not os.path.isfile(wordlist):
            logger.warning(f"Wordlist not found: {wordlist}, skipping brute-force")
            return set()

        await self.report_progress(40, f"Running puredns brute-force ({profile})...")

        rate_limit = "200" if profile == "stealth" else "500"
        timeout = 600 if profile in ("full", "bounty") else 180

        try:
            result = await self.run_command(
                [
                    "puredns", "bruteforce", wordlist, domain,
                    "--resolvers", self.RESOLVERS,
                    "--rate-limit", rate_limit,
                    "--wildcard-batch", "1000000",
                ],
                timeout=timeout,
            )
            subdomains = set()
            if result["returncode"] == 0 and result["stdout"].strip():
                for line in result["stdout"].strip().split("\n"):
                    sub = line.strip().lower()
                    if sub and (sub.endswith(f".{domain}") or sub == domain):
                        subdomains.add(sub)
            logger.info(f"puredns found {len(subdomains)} subdomains")
            return subdomains
        except Exception as e:
            logger.warning(f"puredns brute-force failed: {e}")
            return set()

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



# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.subdomain.run_subdomain_agent")
def run_subdomain_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    """Celery task wrapper — runs the async agent in an event loop."""
    import asyncio
    agent = SubdomainAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
