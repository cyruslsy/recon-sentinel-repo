"""
Recon Sentinel — SSL/TLS Agent
Tool: openssl s_client (async subprocess)
MITRE: T1190 (Exploit Public-Facing Application)
Checks: certificate validity, expiry, weak ciphers, protocol versions
"""

import asyncio
import hashlib
import logging
import re
from datetime import datetime

from app.agents.base import BaseAgent
from app.core.tz import utc_now
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)


class SSLTLSAgent(BaseAgent):
    agent_type = "ssl_tls"
    agent_name = "SSL/TLS Analysis Agent"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1190"]

    async def execute(self) -> list[dict]:
        target = self.target_value
        if ":" not in target:
            target = f"{target}:443"

        findings = []

        # ─── Certificate Info ─────────────────────────────────
        await self.report_progress(20, "Checking certificate...")
        cert_info = await self._get_cert_info(target)
        if cert_info:
            # Check expiry
            expiry = cert_info.get("expiry")
            if expiry:
                days_left = (expiry - utc_now()).days
                if days_left < 0:
                    findings.append(self._make("certificate_expired",
                        f"SSL certificate EXPIRED ({abs(days_left)} days ago)",
                        FindingSeverity.CRITICAL, cert_info))
                elif days_left < 30:
                    findings.append(self._make("certificate_expiring_soon",
                        f"SSL certificate expires in {days_left} days",
                        FindingSeverity.MEDIUM, cert_info))
                else:
                    findings.append(self._make("certificate_valid",
                        f"SSL certificate valid for {days_left} days. Issuer: {cert_info.get('issuer', 'unknown')}",
                        FindingSeverity.INFO, cert_info))

            # Check self-signed
            if cert_info.get("self_signed"):
                findings.append(self._make("self_signed_certificate",
                    "Self-signed certificate detected",
                    FindingSeverity.HIGH, cert_info))

        # ─── Protocol Versions ────────────────────────────────
        await self.report_progress(50, "Checking TLS versions...")
        for proto in ["ssl3", "tls1", "tls1_1"]:
            supported = await self._check_protocol(target, proto)
            if supported:
                sev = FindingSeverity.CRITICAL if proto == "ssl3" else FindingSeverity.HIGH
                findings.append(self._make(f"deprecated_{proto}",
                    f"Deprecated protocol supported: {proto.upper().replace('_', '.')}",
                    sev, {"protocol": proto}))

        # ─── Weak Ciphers ─────────────────────────────────────
        await self.report_progress(75, "Checking cipher suites...")
        weak_ciphers = await self._check_weak_ciphers(target)
        if weak_ciphers:
            findings.append(self._make("weak_ciphers",
                f"Weak cipher suites supported: {', '.join(weak_ciphers[:5])}",
                FindingSeverity.MEDIUM,
                {"weak_ciphers": weak_ciphers}))

        return findings

    def _make(self, value: str, detail: str, severity: FindingSeverity, raw: dict) -> dict:
        return {
            "finding_type": FindingType.SSL_TLS,
            "severity": severity,
            "value": value,
            "detail": detail,
            "mitre_technique_ids": ["T1190"],
            "fingerprint": hashlib.sha256(f"ssl:{self.target_value}:{value}".encode()).hexdigest()[:32],
            "raw_data": raw,
        }

    async def _get_cert_info(self, target: str) -> dict | None:
        try:
            host = target.split(":")[0]

            # Validate target format to prevent injection
            if not all(c.isalnum() or c in ".-:" for c in target):
                logger.warning(f"Invalid target format for SSL check: {target}")
                return None

            # Use two-stage pipe: s_client feeds into x509 parser
            # Stage 1: Get raw cert
            proc1 = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", target, "-servername", host,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            cert_pem, _ = await asyncio.wait_for(proc1.communicate(input=b""), timeout=15)

            # Stage 2: Parse cert dates/issuer/subject
            proc2 = await asyncio.create_subprocess_exec(
                "openssl", "x509", "-noout", "-dates", "-issuer", "-subject",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            parsed, _ = await asyncio.wait_for(proc2.communicate(input=cert_pem), timeout=10)

            info = {}
            for line in parsed.decode("utf-8", errors="replace").split("\n"):
                if "notAfter=" in line:
                    date_str = line.split("=", 1)[1].strip()
                    try:
                        info["expiry"] = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    except ValueError:
                        pass
                if "issuer=" in line:
                    info["issuer"] = line.split("=", 1)[1].strip()[:100]
                if "subject=" in line:
                    info["subject"] = line.split("=", 1)[1].strip()[:100]

            info["self_signed"] = info.get("issuer", "") == info.get("subject", "") and info.get("issuer", "") != ""
            return info if info else None
        except Exception as e:
            logger.warning(f"Certificate check failed: {e}")
            return None

    async def _check_protocol(self, target: str, protocol: str) -> bool:
        flag_map = {"ssl3": "-ssl3", "tls1": "-tls1", "tls1_1": "-tls1_1"}
        flag = flag_map.get(protocol)
        if not flag:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", target, flag,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=b""), timeout=10)
            out = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
            return "CONNECTED" in out and "error" not in err.lower()
        except Exception:
            return False

    async def _check_weak_ciphers(self, target: str) -> list[str]:
        weak = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", target,
                "-cipher", "LOW:EXP:NULL:RC4:DES:3DES",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=b""), timeout=10)
            out = stdout.decode("utf-8", errors="replace")
            if "CONNECTED" in out:
                cipher_match = re.search(r"Cipher\s+:\s+(\S+)", out)
                if cipher_match and cipher_match.group(1) != "0000":
                    weak.append(cipher_match.group(1))
        except Exception:
            pass
        return weak


@celery_app.task(name="app.agents.ssl_tls.run_ssl_tls_agent")
def run_ssl_tls_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    return asyncio.run(SSLTLSAgent(scan_id, target_value, project_id, config).run())
