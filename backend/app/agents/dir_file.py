"""
Recon Sentinel — Directory & File Discovery Agent
Tool: ffuf (primary)
MITRE: T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts — admin panels)

Wordlist strategy (tiered, tech-adaptive):
  Tier 1: Base wordlist sized by scan profile (quick=common.txt, full=raft-medium, bounty=raft-large)
  Tier 2: Tech-adaptive lists added when technologies detected (WordPress, Spring, PHP, etc.)
  Tier 3: Sensitive file checks (always included — .git, .env, backup.sql, etc.)
  Tier 4: User-uploaded custom wordlists (from scan config)

Self-correction:
  - Custom 404 detection → re-run with -fs {size}
  - WAF blocking → reduce rate + rotate user-agent
  - Rate limiting → backoff + reduce threads
"""

import hashlib
import logging
import os
import tempfile
import uuid

from app.agents.base import BaseAgent
from app.agents.corrections import (
    Custom404Detector, WAFDetector, RateLimitDetector, CorrectionResult,
)
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.enums import FindingSeverity, FindingType, HealthEventType, ScanPhase
from app.models.models import Finding

logger = logging.getLogger(__name__)

ADMIN_PATHS = {
    "/admin", "/wp-admin", "/administrator", "/login", "/dashboard",
    "/panel", "/manage", "/console", "/portal", "/cpanel",
    "/.env", "/config", "/backup", "/db", "/phpmyadmin",
}

INTERESTING_EXTENSIONS = {".bak", ".sql", ".zip", ".tar.gz", ".env", ".config", ".xml", ".json", ".yml"}

# ─── Wordlist Configuration ──────────────────────────────────

# Tier 1: Base wordlists by scan profile (SecLists paths)
PROFILE_WORDLISTS = {
    "quick": ["/usr/share/seclists/Discovery/Web-Content/common.txt"],
    "passive_only": ["/usr/share/seclists/Discovery/Web-Content/common.txt"],
    "stealth": ["/usr/share/seclists/Discovery/Web-Content/common.txt"],
    "full": [
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
    ],
    "bounty": [
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
    ],
}

# Tier 2: Tech-adaptive wordlists (added when technology is detected)
TECH_WORDLISTS = {
    "wordpress": "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    "wp-admin": "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    "joomla": "/usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt",
    "drupal": "/usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt",
    "php": "/usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt",
    "laravel": "/usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt",
    "spring": "/usr/share/seclists/Discovery/Web-Content/spring-boot.txt",
    "java": "/usr/share/seclists/Discovery/Web-Content/spring-boot.txt",
    "tomcat": "/usr/share/seclists/Discovery/Web-Content/tomcat.txt",
    "iis": "/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt",
    "asp.net": "/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt",
    "nginx": "/usr/share/seclists/Discovery/Web-Content/nginx.txt",
    "apache": "/usr/share/seclists/Discovery/Web-Content/apache.txt",
    "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "graphql": "/usr/share/seclists/Discovery/Web-Content/graphql.txt",
    "nodejs": "/usr/share/seclists/Discovery/Web-Content/nodejs.txt",
    "express": "/usr/share/seclists/Discovery/Web-Content/nodejs.txt",
    "django": "/usr/share/seclists/Discovery/Web-Content/django.txt",
    "flask": "/usr/share/seclists/Discovery/Web-Content/flask.txt",
    "ruby": "/usr/share/seclists/Discovery/Web-Content/ruby.txt",
    "rails": "/usr/share/seclists/Discovery/Web-Content/ror.txt",
}

# Tier 3: Sensitive files that should always be checked (small, high-value)
SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".gitignore",
    ".env", ".env.local", ".env.production", ".env.backup",
    "web.config", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "wp-config.php.bak", "config.php.bak", "database.yml",
    "backup.sql", "dump.sql", "db.sql", "data.sql",
    "backup.zip", "backup.tar.gz", "site.zip",
    "phpinfo.php", "info.php", "test.php",
    "server-status", "server-info",
    ".DS_Store", "Thumbs.db",
    "package.json", "composer.json", "Gemfile",
    ".svn/entries", ".svn/wc.db",
    ".hg/store/00manifest.i",
    "CHANGELOG.md", "README.md", "LICENSE",
    "Dockerfile", "docker-compose.yml",
    "swagger.json", "openapi.json", "api-docs",
    "graphql", "graphiql",
    "wp-login.php", "administrator/index.php",
    "elmah.axd", "trace.axd",
    "actuator", "actuator/health", "actuator/env",
]


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

        # ─── Wordlist Assembly (tiered, tech-adaptive) ──────────
        wordlist_path = await self._build_wordlist()
        logger.info(f"Assembled wordlist at {wordlist_path}")

        # ─── Phase 1: Initial ffuf run ────────────────────────
        await self.report_progress(10, "Running ffuf...")
        raw_results = await self._run_ffuf(target, wordlist_path)

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
            raw_results = await self._run_ffuf(target, wordlist_path)

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

    # ─── Wordlist Assembly ──────────────────────────────────────

    async def _build_wordlist(self) -> str:
        """Build a merged wordlist from 4 tiers:
        1. Base wordlist (profile-sized)
        2. Tech-adaptive wordlists (from detected technologies)
        3. Sensitive file paths (always included)
        4. Custom user wordlists (from config)
        Returns path to a temp file containing the merged, deduplicated wordlist."""
        words = set()

        # Tier 1: Base wordlist from scan profile
        profile = self.config.get("profile", "full")
        base_lists = PROFILE_WORDLISTS.get(profile, PROFILE_WORDLISTS["full"])

        # Allow config override
        if self.config.get("wordlist"):
            base_lists = [self.config["wordlist"]]

        for wl_path in base_lists:
            if os.path.exists(wl_path):
                try:
                    with open(wl_path, "r", errors="ignore") as f:
                        for line in f:
                            word = line.strip()
                            if word and not word.startswith("#"):
                                words.add(word)
                except OSError:
                    logger.warning(f"Cannot read wordlist: {wl_path}")
            else:
                logger.warning(f"Wordlist not found: {wl_path}")

        # Tier 2: Tech-adaptive wordlists from detected technologies
        detected_techs = await self._detect_technologies()
        tech_lists_added = []
        for tech in detected_techs:
            tech_lower = tech.lower()
            for key, wl_path in TECH_WORDLISTS.items():
                if key in tech_lower and os.path.exists(wl_path):
                    if wl_path not in tech_lists_added:
                        tech_lists_added.append(wl_path)
                        try:
                            with open(wl_path, "r", errors="ignore") as f:
                                count_before = len(words)
                                for line in f:
                                    word = line.strip()
                                    if word and not word.startswith("#"):
                                        words.add(word)
                                added = len(words) - count_before
                                logger.info(f"Tech wordlist: +{added} paths from {wl_path} (detected: {tech})")
                        except OSError:
                            pass

        # Tier 3: Sensitive file paths (always included)
        for path in SENSITIVE_PATHS:
            words.add(path)

        # Tier 4: Custom user wordlists from config
        custom_lists = self.config.get("custom_wordlists", [])
        for custom_path in custom_lists:
            if os.path.exists(custom_path):
                try:
                    with open(custom_path, "r", errors="ignore") as f:
                        for line in f:
                            word = line.strip()
                            if word and not word.startswith("#"):
                                words.add(word)
                    logger.info(f"Custom wordlist: {custom_path}")
                except OSError:
                    pass

        # Fallback if no wordlists loaded
        if not words:
            words = set(SENSITIVE_PATHS)
            logger.warning("No wordlists loaded — using sensitive paths only")

        # Write merged wordlist to temp file
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="recon_wordlist_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(sorted(words)))

        logger.info(f"Assembled wordlist: {len(words)} entries (profile={profile}, tech_lists={len(tech_lists_added)})")
        return path

    async def _detect_technologies(self) -> list[str]:
        """Get technologies detected by earlier agents for this scan."""
        techs = set()
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.raw_data, Finding.tags)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
            )
            for raw_data, tags in result.all():
                if tags:
                    for tag in tags:
                        techs.add(tag)
                if raw_data and isinstance(raw_data, dict):
                    for tech in raw_data.get("tech_detected", []):
                        techs.add(tech)
        return list(techs)

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
        """Run all 11 self-correction detectors against ffuf results."""
        from app.agents.corrections import detect_anomalies
        return detect_anomalies(results)

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

@celery_app.task(name="app.agents.dir_file.run_dir_file_agent")
def run_dir_file_agent(scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    agent = DirFileAgent(scan_id, target_value, project_id, config)
    return asyncio.run(agent.run())
