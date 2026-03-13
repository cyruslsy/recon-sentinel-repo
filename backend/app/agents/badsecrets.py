"""
Recon Sentinel — Bad Secrets Agent
Detects known/weak cryptographic secrets across web frameworks.
Inspired by BBOT's badsecrets module (blacklanternsecurity/badsecrets).

Checks discovered web hosts for:
  - ASP.NET ViewState with known MachineKeys (→ RCE)
  - Telerik UI known encryption/hash keys (→ RCE)
  - Flask signed cookies with weak secrets
  - Ruby on Rails known secret_key_base
  - JSF (Mojarra/MyFaces) known ViewState keys
  - Symfony _fragment known HMAC keys
  - Express.js session cookies with known secrets
  - Generic JWT with weak signing keys

MITRE: T1078 (Valid Accounts), T1190 (Exploit Public-Facing Application)

Flow:
  1. Load discovered live web hosts from earlier phases
  2. For each host, fetch the root page
  3. Carve cryptographic products from HTML (viewstates, cookies, etc.)
  4. Check carved products against badsecrets library
  5. Report confirmed known-secret findings (these are typically critical/high)
"""

import hashlib
import logging
import uuid

import httpx

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.enums import FindingSeverity, FindingType, ScanPhase, HealthEventType
from app.models.models import Finding

logger = logging.getLogger(__name__)

# Severity mapping: badsecrets module name → impact assessment
# Known machinekeys/telerik keys are critical because they lead to RCE
MODULE_SEVERITY = {
    "ASPNET_Viewstate": FindingSeverity.CRITICAL,  # Known machinekey → ViewState deserialization → RCE
    "Telerik_HashKey": FindingSeverity.CRITICAL,    # Known hash key → file upload → RCE
    "Telerik_EncryptionKey": FindingSeverity.CRITICAL,
    "Flask_SignedCookies": FindingSeverity.HIGH,     # Session forgery → privilege escalation
    "Rails_SecretKeyBase": FindingSeverity.HIGH,     # Cookie tampering → potential RCE via deserialization
    "Jsf_Viewstate": FindingSeverity.CRITICAL,       # Known key → deserialization → RCE
    "Symfony_SignedURL": FindingSeverity.HIGH,        # _fragment RCE
    "Express_SignedCookies": FindingSeverity.MEDIUM,  # Session forgery
    "Generic_JWT": FindingSeverity.HIGH,              # Token forgery → auth bypass
}

# MITRE mapping per module
MODULE_MITRE = {
    "ASPNET_Viewstate": ["T1190", "T1059"],    # Exploit + Code Execution
    "Telerik_HashKey": ["T1190", "T1059"],
    "Telerik_EncryptionKey": ["T1190", "T1059"],
    "Flask_SignedCookies": ["T1078"],           # Valid Accounts (session forgery)
    "Rails_SecretKeyBase": ["T1078", "T1190"],
    "Jsf_Viewstate": ["T1190", "T1059"],
    "Symfony_SignedURL": ["T1190", "T1059"],
    "Express_SignedCookies": ["T1078"],
    "Generic_JWT": ["T1078"],
}


class BadSecretsAgent(BaseAgent):
    agent_type = "badsecrets"
    agent_name = "Bad Secrets Agent"
    phase = ScanPhase.VULN
    mitre_tags = ["T1078", "T1190"]
    max_retries = 1

    async def execute(self) -> list[dict]:
        findings = []

        # ─── Phase 1: Get all live web hosts ──────────────────
        await self.report_progress(5, "Loading discovered web hosts...")
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.value)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
                .where(Finding.finding_type.in_([
                    FindingType.SUBDOMAIN,
                    FindingType.PORT,
                ]))
            )
            hosts = list(set(r[0] for r in result.all()))

        # Add base domain
        if self.target_value not in hosts:
            hosts.append(self.target_value)

        # Clean hosts — ensure they have scheme
        web_hosts = []
        for h in hosts:
            h = h.strip().rstrip("/")
            if h.startswith("http://") or h.startswith("https://"):
                web_hosts.append(h)
            elif ":" in h and not h.startswith("http"):
                # port-style finding like "target.com:443"
                port = h.split(":")[-1]
                host_part = h.rsplit(":", 1)[0]
                if port == "443":
                    web_hosts.append(f"https://{host_part}")
                elif port in ("80", "8080", "8443", "8000", "3000"):
                    scheme = "https" if port in ("443", "8443") else "http"
                    web_hosts.append(f"{scheme}://{host_part}:{port}")
            else:
                web_hosts.append(f"https://{h}")
                web_hosts.append(f"http://{h}")

        # Deduplicate
        web_hosts = list(set(web_hosts))[:100]  # Cap at 100 hosts

        if not web_hosts:
            return []

        await self.report_progress(10, f"Scanning {len(web_hosts)} web hosts for known secrets...")

        # ─── Phase 2: Check each host ─────────────────────────
        try:
            from badsecrets import modules_loaded
            has_badsecrets = True
        except ImportError:
            has_badsecrets = False
            logger.warning("badsecrets library not installed — falling back to regex-based detection")

        # Reuse a single httpx client across all hosts (R10 P2 fix)
        import warnings
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            for i, host in enumerate(web_hosts):
                try:
                    if has_badsecrets:
                        host_findings = await self._check_with_badsecrets(host, modules_loaded, client)
                    else:
                        host_findings = await self._check_with_regex(host, client)

                    findings.extend(host_findings)
                except Exception as e:
                    logger.debug(f"Error checking {host}: {e}")

                if i % 10 == 0:
                    await self.report_progress(
                        10 + int(80 * i / max(len(web_hosts), 1)),
                        f"Checked {i+1}/{len(web_hosts)} — {len(findings)} secrets found",
                )

        if findings:
            async with AsyncSessionLocal() as db:
                await self._create_health_event(
                    db, HealthEventType.ANOMALY_DETECTED,
                    f"Known secrets detected on {len(findings)} endpoints",
                    f"Bad Secrets Agent found {len(findings)} endpoints using known/weak "
                    f"cryptographic secrets. These are typically critical — known ASP.NET "
                    f"MachineKeys and Telerik keys lead directly to RCE.",
                )

        return findings

    async def _check_with_badsecrets(self, url: str, modules_loaded: dict, client: httpx.AsyncClient) -> list[dict]:
        """Use the badsecrets library for comprehensive detection."""
        findings = []

        try:
            resp = await client.get(url)

            # Use badsecrets carve_all_modules to check all frameworks
            from badsecrets.base import check_all_modules
            results = check_all_modules(resp.text, url=url)

            for r in results:
                detecting_module = r.get("detecting_module", "unknown")
                secret = r.get("secret", "")
                description = r.get("description", {})
                product = description.get("product", detecting_module)

                severity = MODULE_SEVERITY.get(detecting_module, FindingSeverity.HIGH)
                mitre_ids = MODULE_MITRE.get(detecting_module, ["T1078", "T1190"])

                fp = hashlib.sha256(
                    f"badsecret:{detecting_module}:{url}:{secret[:20]}".encode()
                ).hexdigest()[:32]

                findings.append({
                    "finding_type": FindingType.VULNERABILITY,
                    "severity": severity,
                    "value": f"KNOWN SECRET: {product} — {url}",
                    "detail": (
                        f"Known {product} secret detected via {detecting_module}. "
                        f"Secret: '{secret[:40]}{'...' if len(secret) > 40 else ''}'. "
                        f"This typically leads to {'RCE via deserialization' if severity == FindingSeverity.CRITICAL else 'session forgery / privilege escalation'}."
                    ),
                    "mitre_technique_ids": sorted(set(mitre_ids)),
                    "fingerprint": fp,
                    "tags": [
                        "badsecrets", "known_secret",
                        detecting_module.lower(),
                        "rce" if severity == FindingSeverity.CRITICAL else "auth_bypass",
                    ],
                    "raw_data": {
                        "detecting_module": detecting_module,
                        "url": url,
                        "product": product,
                        "secret_preview": secret[:20] + "..." if len(secret) > 20 else secret,
                        "description": description,
                    },
                })

        except httpx.RequestError:
            pass

        return findings

    async def _check_with_regex(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        """Fallback: regex-based detection for common known-secret indicators.
        Less comprehensive than badsecrets library but catches the most critical cases."""
        import re
        findings = []

        try:
            resp = await client.get(url)
            body = resp.text[:50000]  # First 50KB
            headers = dict(resp.headers)

            # Check 1: ASP.NET ViewState present (potential for known key check)
            viewstate_match = re.search(
                r'__VIEWSTATE[^>]*value="([A-Za-z0-9+/=]{20,})"', body
            )
            generator_match = re.search(
                r'__VIEWSTATEGENERATOR[^>]*value="([A-Fa-f0-9]{8})"', body
            )
            if viewstate_match and generator_match:
                fp = hashlib.sha256(
                    f"viewstate:{url}:{generator_match.group(1)}".encode()
                ).hexdigest()[:32]
                findings.append({
                    "finding_type": FindingType.VULNERABILITY,
                    "severity": FindingSeverity.MEDIUM,
                    "value": f"ASP.NET ViewState detected — {url}",
                    "detail": (
                        f"ASP.NET ViewState with generator {generator_match.group(1)} found. "
                        f"Install badsecrets library for full known-key checking. "
                        f"If MachineKey is known, this leads to RCE via deserialization."
                    ),
                    "mitre_technique_ids": ["T1190"],
                    "fingerprint": fp,
                    "tags": ["badsecrets", "viewstate", "aspnet", "needs_badsecrets_lib"],
                    "raw_data": {
                        "url": url,
                        "generator": generator_match.group(1),
                        "viewstate_length": len(viewstate_match.group(1)),
                    },
                })

            # Check 2: Telerik indicators
            if "Telerik.Web.UI" in body or "telerik" in body.lower():
                fp = hashlib.sha256(f"telerik:{url}".encode()).hexdigest()[:32]
                findings.append({
                    "finding_type": FindingType.VULNERABILITY,
                    "severity": FindingSeverity.MEDIUM,
                    "value": f"Telerik UI detected — {url}",
                    "detail": (
                        f"Telerik Web UI components detected. Install badsecrets library "
                        f"for known encryption/hash key checking. Known Telerik keys "
                        f"lead to arbitrary file upload → RCE."
                    ),
                    "mitre_technique_ids": ["T1190"],
                    "fingerprint": fp,
                    "tags": ["badsecrets", "telerik", "needs_badsecrets_lib"],
                    "raw_data": {"url": url},
                })

            # Check 3: Flask/Express session cookies with weak signatures
            for cookie_name, cookie_val in resp.cookies.items():
                # Flask sessions start with eyJ (base64 JSON) followed by a dot-separated signature
                if cookie_val.startswith("eyJ") and cookie_val.count(".") >= 1:
                    fp = hashlib.sha256(
                        f"session:{url}:{cookie_name}".encode()
                    ).hexdigest()[:32]
                    findings.append({
                        "finding_type": FindingType.VULNERABILITY,
                        "severity": FindingSeverity.LOW,
                        "value": f"Signed session cookie detected — {url}",
                        "detail": (
                            f"Signed session cookie '{cookie_name}' found. "
                            f"Install badsecrets library for known secret key checking. "
                            f"Weak signing keys allow session forgery."
                        ),
                        "mitre_technique_ids": ["T1078"],
                        "fingerprint": fp,
                        "tags": ["badsecrets", "session_cookie", "needs_badsecrets_lib"],
                        "raw_data": {"url": url, "cookie_name": cookie_name},
                    })

        except httpx.RequestError:
            pass

        return findings


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.badsecrets.run_badsecrets_agent")
def run_badsecrets_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(BadSecretsAgent(scan_id, target_value, project_id, config).run())
