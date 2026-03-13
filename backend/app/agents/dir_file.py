"""
Recon Sentinel — Directory & File Discovery Agent
Tool: ffuf (primary)
MITRE: T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts — admin panels)

Self-correction:
  - Custom 404 detection → re-run with -fs {size}
  - WAF blocking → reduce rate + rotate user-agent
  - Rate limiting → backoff + reduce threads
"""

import hashlib
import logging

from app.agents.base import BaseAgent
from app.agents.corrections import (
    Custom404Detector, WAFDetector, RateLimitDetector, CorrectionResult,
)
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.enums import FindingSeverity, FindingType, HealthEventType, ScanPhase

logger = logging.getLogger(__name__)

ADMIN_PATHS = {
    "/admin", "/wp-admin", "/administrator", "/login", "/dashboard",
    "/panel", "/manage", "/console", "/portal", "/cpanel",
    "/.env", "/config", "/backup", "/db", "/phpmyadmin",
}

INTERESTING_EXTENSIONS = {".bak", ".sql", ".zip", ".tar.gz", ".env", ".config", ".xml", ".json", ".yml"}


class DirFileAgent(BaseAgent):
    agent_type = "dir_file"
    agent_name = "Directory & File Discovery Agent"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1190", "T1078"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._filter_size: int | None = None
        self._filter_words: int | None = None
        self._rate_limit: int = self.config.get("rate_limit", 100)
        self._threads: int = self.config.get("threads", 10)
        self._user_agent: str | None = None
        self._delay: float = 0

    async def execute(self) -> list[dict]:
        target = self.target_value
        if not target.startswith("http"):
            target = f"https://{target}"

        wordlist = self.config.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")

        # ─── Phase 1: Initial ffuf run ────────────────────────
        await self.report_progress(10, "Running ffuf...")
        raw_results = await self._run_ffuf(target, wordlist)

        # ─── Phase 2: Self-correction checks ──────────────────
        await self.report_progress(50, "Analyzing responses...")
        corrections = self._check_for_anomalies(raw_results)

        if corrections:
            for correction in corrections:
                logger.info(f"Correction needed: {correction.pattern}")

                if correction.pattern == "custom_404":
                    self._filter_size = correction.corrected_params["filter_size"]
                elif correction.pattern == "waf_blocking":
                    self._rate_limit = correction.corrected_params["new_rate"]
                    self._delay = correction.corrected_params["add_delay"]
                    self._user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
                elif correction.pattern == "rate_limiting":
                    self._threads = correction.corrected_params["new_threads"]
                    self._delay = correction.corrected_params["backoff_seconds"]

                # Create health event for each correction
                async with AsyncSessionLocal() as db:
                    await self._create_health_event(
                        db, HealthEventType.SELF_CORRECTION,
                        f"Self-correction: {correction.pattern}",
                        correction.detail,
                    )

            # ─── Phase 3: Re-run with corrections ─────────────
            await self.report_progress(60, "Re-running with corrections...")
            raw_results = await self._run_ffuf(target, wordlist)

            # Verify correction worked
            new_corrections = self._check_for_anomalies(raw_results)
            if not new_corrections:
                async with AsyncSessionLocal() as db:
                    await self._create_health_event(
                        db, HealthEventType.CORRECTION_SUCCESS,
                        "Self-correction succeeded",
                        f"Re-run after correction produced {len(raw_results)} clean results.",
                    )

        # ─── Phase 4: Build findings ──────────────────────────
        await self.report_progress(80, "Building findings...")
        findings = []
        for r in raw_results:
            path = r.get("path", "")
            status = r.get("status", 0)
            length = r.get("content_length", 0)

            severity = self._classify_severity(path, status)
            tags = self._classify_tags(path)

            fingerprint = hashlib.sha256(f"dir:{target}{path}".encode()).hexdigest()[:32]

            findings.append({
                "finding_type": FindingType.DIRECTORY,
                "severity": severity,
                "value": f"{target}{path}",
                "detail": f"HTTP {status} | {length} bytes | {', '.join(tags) if tags else 'directory'}",
                "mitre_technique_ids": ["T1190"] + (["T1078"] if "admin_panel" in tags else []),
                "fingerprint": fingerprint,
                "tags": tags,
                "raw_data": {
                    "host": target,
                    "path": path,
                    "status": status,
                    "content_length": length,
                    "content_type": r.get("content_type", ""),
                    "redirect_url": r.get("redirect_url", ""),
                },
            })

        return findings

    # ─── ffuf Execution ───────────────────────────────────────

    async def _run_ffuf(self, target: str, wordlist: str) -> list[dict]:
        cmd = [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,301,302,307,401,403,405,500",
            "-t", str(self._threads),
            "-rate", str(self._rate_limit),
            "-json",
            "-s",  # silent (no banner)
        ]

        if self._filter_size is not None:
            cmd.extend(["-fs", str(self._filter_size)])
        if self._filter_words is not None:
            cmd.extend(["-fw", str(self._filter_words)])
        if self._user_agent:
            cmd.extend(["-H", f"User-Agent: {self._user_agent}"])
        if self._delay > 0:
            cmd.extend(["-p", str(self._delay)])

        try:
            result = await self.run_command(cmd, timeout=300, parse_json=True)
            if result["parsed"]:
                return [
                    {
                        "path": "/" + entry.get("input", {}).get("FUZZ", ""),
                        "status": entry.get("status", 0),
                        "content_length": entry.get("length", 0),
                        "content_type": entry.get("content-type", ""),
                        "word_count": entry.get("words", 0),
                        "redirect_url": entry.get("redirectlocation", ""),
                    }
                    for entry in result["parsed"]
                    if entry.get("status")
                ]
            return []
        except Exception as e:
            logger.warning(f"ffuf failed: {e}")
            return []

    # ─── Anomaly Detection ────────────────────────────────────

    def _check_for_anomalies(self, results: list[dict]) -> list[CorrectionResult]:
        corrections = []

        c404 = Custom404Detector.detect(results)
        if c404:
            corrections.append(c404)

        waf = WAFDetector.detect(results)
        if waf:
            corrections.append(waf)

        rl = RateLimitDetector.detect(results)
        if rl:
            corrections.append(rl)

        return corrections

    # ─── Classification ───────────────────────────────────────

    @staticmethod
    def _classify_severity(path: str, status: int) -> FindingSeverity:
        path_lower = path.lower()
        if any(p in path_lower for p in ("/.env", "/config", "/backup", "/.git", "/db")):
            return FindingSeverity.HIGH
        if any(p in path_lower for p in ADMIN_PATHS):
            return FindingSeverity.MEDIUM
        if status in (401, 403):
            return FindingSeverity.LOW
        return FindingSeverity.INFO

    @staticmethod
    def _classify_tags(path: str) -> list[str]:
        tags = []
        path_lower = path.lower()
        if any(p in path_lower for p in ADMIN_PATHS):
            tags.append("admin_panel")
        if any(path_lower.endswith(ext) for ext in INTERESTING_EXTENSIONS):
            tags.append("backup_file")
        if "/.git" in path_lower or "/.svn" in path_lower:
            tags.append("source_code_exposure")
        if "api" in path_lower:
            tags.append("api_endpoint")
        return tags


# ─── Celery Task ──────────────────────────────────────────────

@celery_app.task(name="app.agents.dir_file.run_dir_file_agent", bind=True)
def run_dir_file_agent(self, scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    agent = DirFileAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
