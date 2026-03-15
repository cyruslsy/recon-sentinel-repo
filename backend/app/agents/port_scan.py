"""
Recon Sentinel — Port & Service Scan Agent
Tools: Naabu (fast SYN scan), Nmap (service version detection)
MITRE: T1595 (Active Scanning)

Self-correction: If Nmap returns 0 results with all ports filtered,
switch from SYN to Connect scan + add -Pn (skip host discovery).
"""

import hashlib
import logging
import xml.etree.ElementTree as ET

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.models.enums import FindingSeverity, FindingType, ScanPhase

logger = logging.getLogger(__name__)


class PortScanAgent(BaseAgent):
    agent_type = "port_scan"
    agent_name = "Port & Service Scan Agent"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1595"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._use_connect_scan = False  # Self-correction flag
        self._skip_host_discovery = False

    # C3: Non-standard ports for common services detected via tech context
    TECH_PORTS = {
        "mongodb": [27017, 27018, 27019],
        "redis": [6379],
        "elasticsearch": [9200, 9300],
        "docker": [2375, 2376],
        "kubernetes": [6443, 10250],
        "postgresql": [5432],
        "mysql": [3306],
        "mssql": [1433],
        "cassandra": [9042],
        "memcached": [11211],
        "rabbitmq": [5672, 15672],
        "kafka": [9092],
        "jenkins": [8080, 50000],
        "grafana": [3000],
        "prometheus": [9090],
    }

    async def execute(self) -> list[dict]:
        """Run Naabu for port discovery, then Nmap for service detection."""
        target = self.target_value

        # ─── C3: Get tech-specific extra ports ──────────────────
        extra_ports = await self._get_tech_ports()

        # ─── Phase 1: Fast Port Discovery (Naabu) ────────────
        await self.report_progress(10, "Running Naabu...")
        open_ports = await self._run_naabu(target, extra_ports=extra_ports)

        if not open_ports:
            logger.info(f"Naabu found 0 open ports on {target}")
            return []

        await self.report_progress(40, f"Found {len(open_ports)} ports, running Nmap...")

        # ─── Phase 2: Service Detection (Nmap) ───────────────
        findings = await self._run_nmap(target, open_ports)

        return findings

    # ─── Naabu ────────────────────────────────────────────────

    async def _get_tech_ports(self) -> list[int]:
        """C3: Get extra ports based on technologies detected in earlier phases."""
        try:
            from app.agents.tech_context import get_scan_tech_context
            tech_ctx = await get_scan_tech_context(self.scan_id)
            extra = set()
            for tech in tech_ctx.detected_techs:
                tech_lower = tech.lower()
                for key, ports in self.TECH_PORTS.items():
                    if key in tech_lower:
                        extra.update(ports)
            if extra:
                logger.info(f"C3: Adding {len(extra)} tech-specific ports: {sorted(extra)}")
            return sorted(extra)
        except Exception as e:
            logger.warning(f"C3: Tech port detection failed: {e}")
            return []

    async def _run_naabu(self, target: str, extra_ports: list[int] | None = None) -> list[int]:
        """Fast SYN port discovery with Naabu."""
        rate_limit = self.config.get("rate_limit", 1000)
        top_ports = self.config.get("top_ports", "1000")

        cmd = [
            "naabu",
            "-host", target,
            "-top-ports", str(top_ports),
            "-rate", str(rate_limit),
            "-silent",
            "-json",
        ]

        # C3: Add tech-specific ports to scan
        if extra_ports:
            cmd.extend(["-p", ",".join(str(p) for p in extra_ports)])

        try:
            result = await self.run_command(cmd, timeout=180, parse_json=True)
            ports = set()
            if result["parsed"]:
                for entry in result["parsed"]:
                    port = entry.get("port")
                    if port:
                        ports.add(int(port))
            return sorted(ports)
        except Exception as e:
            logger.warning(f"Naabu failed: {e}")
            return []

    # ─── Nmap ─────────────────────────────────────────────────

    async def _run_nmap(self, target: str, ports: list[int]) -> list[dict]:
        """Service version detection with Nmap. Outputs XML for reliable parsing."""
        port_str = ",".join(str(p) for p in ports)
        output_file = f"/tmp/nmap_{hashlib.md5(target.encode()).hexdigest()[:8]}.xml"

        cmd = ["nmap"]

        # Self-correction: switch scan type if firewall detected
        if self._use_connect_scan:
            cmd.append("-sT")   # TCP Connect scan (no raw socket needed)
        else:
            cmd.append("-sT")   # Default to Connect scan (works without root/NET_RAW in some envs)

        if self._skip_host_discovery:
            cmd.append("-Pn")   # Skip host discovery — assume host is up

        cmd.extend([
            "-sV",              # Service version detection
            "--version-intensity", "5",
            "-p", port_str,
            "-T3",              # Normal timing
            "-oX", output_file, # XML output for parsing
            "--open",           # Only show open ports
            target,
        ])

        rate = self.config.get("rate_limit")
        if rate:
            cmd.extend(["--max-rate", str(rate)])

        try:
            result = await self.run_command(cmd, timeout=300)

            if result["returncode"] != 0:
                logger.warning(f"Nmap returned exit code {result['returncode']}: {result['stderr'][:200]}")

            # Parse XML output
            return await self._parse_nmap_xml(output_file, target)

        except Exception as e:
            logger.error(f"Nmap failed: {e}")
            return []

    async def _parse_nmap_xml(self, xml_path: str, target: str) -> list[dict]:
        """Parse Nmap XML output into finding dicts."""
        findings = []

        try:
            # Read the XML file
            result = await self.run_command(["cat", xml_path], timeout=5)
            if not result["stdout"].strip():
                return []

            root = ET.fromstring(result["stdout"])
        except Exception as e:
            logger.warning(f"Failed to parse Nmap XML: {e}")
            return []

        for host in root.findall(".//host"):
            addr_elem = host.find("address[@addrtype='ipv4']")
            host_ip = addr_elem.get("addr", target) if addr_elem is not None else target

            for port_elem in host.findall(".//port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_num = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")

                service = port_elem.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                service_version = ""
                if service is not None:
                    parts = [service.get("product", ""), service.get("version", ""), service.get("extrainfo", "")]
                    service_version = " ".join(p for p in parts if p).strip()

                banner = service.get("servicefp", "") if service is not None else ""

                # Severity based on service type
                severity = self._classify_port_severity(port_num, service_name)

                fingerprint = hashlib.sha256(
                    f"port:{host_ip}:{port_num}:{protocol}".encode()
                ).hexdigest()[:32]

                findings.append({
                    "finding_type": FindingType.PORT,
                    "severity": severity,
                    "value": f"{host_ip}:{port_num}/{protocol}",
                    "detail": f"Open port: {service_name} {service_version}".strip(),
                    "mitre_technique_ids": ["T1595"],
                    "fingerprint": fingerprint,
                    "raw_data": {
                        "host": host_ip,
                        "port": port_num,
                        "protocol": protocol,
                        "service_name": service_name,
                        "service_version": service_version,
                        "banner": banner[:500],
                    },
                })

                await self.report_progress(
                    50 + int(30 * len(findings) / max(len(findings), 1)),
                    f"Detected {service_name} on port {port_num}",
                )

        # Self-correction: detect firewall filtering
        all_filtered = len(findings) == 0
        if all_filtered and not self._use_connect_scan:
            logger.info("All ports filtered — triggering self-correction")
            self._use_connect_scan = True
            self._skip_host_discovery = True
            raise RuntimeError("Firewall detected: 0 open ports, all filtered. Switching to Connect scan + -Pn.")

        return findings

    @staticmethod
    def _classify_port_severity(port: int, service: str) -> FindingSeverity:
        """Classify severity based on exposed service."""
        critical_services = {"mysql", "postgres", "mongodb", "redis", "memcached", "elasticsearch"}
        high_services = {"ssh", "rdp", "vnc", "telnet", "ftp", "smb", "netbios"}
        medium_services = {"http-proxy", "socks", "snmp"}

        service_lower = service.lower()
        if service_lower in critical_services:
            return FindingSeverity.HIGH
        if service_lower in high_services:
            return FindingSeverity.MEDIUM
        if service_lower in medium_services:
            return FindingSeverity.MEDIUM
        if port in (80, 443, 8080, 8443):
            return FindingSeverity.INFO
        return FindingSeverity.LOW

    # ─── Self-Correction Override ─────────────────────────────

    async def self_correct(self, error_context: dict) -> bool:
        """If firewall detected, retry with Connect scan + -Pn."""
        if "Firewall detected" not in error_context.get("error", ""):
            return False

        if self._use_connect_scan:
            # Already tried Connect scan — don't loop
            return False

        self._use_connect_scan = True
        self._skip_host_discovery = True
        logger.info("Self-correcting: switching to Connect scan + -Pn")

        try:
            findings = await self.execute()
        except RuntimeError:
            # Connect scan also returned nothing — that's not a correction failure,
            # just means the host is truly filtered. Return empty success.
            return False

        if findings:
            from app.core.database import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                await self._create_findings(db, findings)
            return True
        return False


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.port_scan.run_port_scan_agent")
def run_port_scan_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    agent = PortScanAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
