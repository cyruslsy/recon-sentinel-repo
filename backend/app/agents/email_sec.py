"""
Recon Sentinel — Email Security Agent
Checks: SPF, DKIM, DMARC records via DNS
MITRE: T1566 (Phishing)
"""

import hashlib
import logging

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)


class EmailSecurityAgent(BaseAgent):
    agent_type = "email_sec"
    agent_name = "Email Security Agent"
    phase = ScanPhase.PASSIVE
    mitre_tags = ["T1566"]

    async def execute(self) -> list[dict]:
        domain = self.target_value
        findings = []

        # ─── SPF ──────────────────────────────────────────────
        await self.report_progress(20, "Checking SPF...")
        spf = await self._dns_txt(domain)
        spf_records = [r for r in spf if "v=spf1" in r.lower()]

        if not spf_records:
            findings.append(self._make_finding(
                domain, "SPF record missing",
                "No SPF record found. Domain is vulnerable to email spoofing.",
                FindingSeverity.HIGH, ["missing_spf"],
            ))
        elif any("-all" in r for r in spf_records):
            findings.append(self._make_finding(
                domain, f"SPF configured (strict): {spf_records[0][:80]}",
                "SPF record with -all (hard fail). Good configuration.",
                FindingSeverity.INFO, ["spf_strict"],
            ))
        elif any("~all" in r for r in spf_records):
            findings.append(self._make_finding(
                domain, f"SPF configured (soft): {spf_records[0][:80]}",
                "SPF record with ~all (soft fail). Consider upgrading to -all.",
                FindingSeverity.LOW, ["spf_soft"],
            ))

        # ─── DMARC ────────────────────────────────────────────
        await self.report_progress(50, "Checking DMARC...")
        dmarc = await self._dns_txt(f"_dmarc.{domain}")
        dmarc_records = [r for r in dmarc if "v=dmarc1" in r.lower()]

        if not dmarc_records:
            findings.append(self._make_finding(
                domain, "DMARC record missing",
                "No DMARC record found. Email authentication not enforced.",
                FindingSeverity.HIGH, ["missing_dmarc"],
            ))
        elif any("p=reject" in r.lower() for r in dmarc_records):
            findings.append(self._make_finding(
                domain, f"DMARC configured (reject): {dmarc_records[0][:80]}",
                "DMARC with p=reject. Strong email authentication.",
                FindingSeverity.INFO, ["dmarc_reject"],
            ))
        elif any("p=none" in r.lower() for r in dmarc_records):
            findings.append(self._make_finding(
                domain, f"DMARC configured (none): {dmarc_records[0][:80]}",
                "DMARC with p=none. Monitoring only — not enforcing.",
                FindingSeverity.MEDIUM, ["dmarc_none"],
            ))

        # ─── DKIM (common selectors) ──────────────────────────
        await self.report_progress(75, "Checking DKIM...")
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
        dkim_found = False
        for sel in dkim_selectors:
            dkim = await self._dns_txt(f"{sel}._domainkey.{domain}")
            if any("v=dkim1" in r.lower() or "p=" in r for r in dkim):
                dkim_found = True
                findings.append(self._make_finding(
                    domain, f"DKIM found (selector: {sel})",
                    f"DKIM record found at {sel}._domainkey.{domain}",
                    FindingSeverity.INFO, ["dkim_found"],
                ))
                break

        if not dkim_found:
            findings.append(self._make_finding(
                domain, "DKIM not found (common selectors checked)",
                f"No DKIM record found for selectors: {', '.join(dkim_selectors)}. May use a custom selector.",
                FindingSeverity.LOW, ["dkim_not_found"],
            ))

        return findings

    def _make_finding(self, domain: str, value: str, detail: str, severity: FindingSeverity, tags: list[str]) -> dict:
        return {
            "finding_type": FindingType.EMAIL_SECURITY,
            "severity": severity,
            "value": value,
            "detail": detail,
            "mitre_technique_ids": ["T1566"],
            "fingerprint": hashlib.sha256(f"email:{domain}:{value[:50]}".encode()).hexdigest()[:32],
            "tags": tags,
        }

    async def _dns_txt(self, hostname: str) -> list[str]:
        try:
            result = await self.run_command(
                ["dig", "+short", hostname, "TXT"],
                timeout=10, silent=True,
            )
            if result["returncode"] == 0 and result["stdout"].strip():
                return [line.strip().strip('"') for line in result["stdout"].strip().split("\n") if line.strip()]
        except Exception:
            pass
        return []


@celery_app.task(name="app.agents.email_sec.run_email_sec_agent")
def run_email_sec_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(EmailSecurityAgent(scan_id, target_value, project_id, config).run())
