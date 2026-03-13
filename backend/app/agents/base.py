"""
Recon Sentinel — Agent Base Class
Every agent inherits from this. Provides:
  - Async subprocess execution (Amendment #10: NEVER subprocess.run)
  - Progress reporting via Redis pub/sub
  - Scope checking before execution
  - Finding creation with MITRE auto-tagging
  - Self-correction hook points (sense → analyze → correct → report)
  - Health event creation for anomaly/correction/escalation
"""

import asyncio
import uuid
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.tz import utc_now
from app.core.redis import publish_scan_event
from app.core.tz import utc_now
from app.models.models import (
from app.core.tz import utc_now
    AgentRun, Finding, HealthEvent, ScopeViolation,
)
from app.models.enums import (
from app.core.tz import utc_now
    AgentStatus, FindingSeverity, FindingType, HealthEventType, ScanPhase,
)

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all 14 specialist agents.

    Subclasses must implement:
      - agent_type: str (e.g., "subdomain", "port_scan")
      - agent_name: str (e.g., "Subdomain Discovery Agent")
      - phase: ScanPhase
      - mitre_tags: list[str] (default MITRE technique IDs for findings)
      - async def execute(self) -> list[dict]  — the actual scanning logic
    
    Optionally override:
      - async def self_correct(self, error_context: dict) -> bool
    """

    agent_type: str = "base"
    agent_name: str = "Base Agent"
    phase: ScanPhase = ScanPhase.PASSIVE
    mitre_tags: list[str] = []
    max_retries: int = 3

    def __init__(self, scan_id: str, target_value: str, project_id: str, config: dict | None = None):
        self.scan_id = scan_id
        self.target_value = target_value
        self.project_id = project_id
        self.config = config or {}
        self.agent_run_id: str | None = None
        self.findings: list[dict] = []
        self.retry_count = 0
        self._progress = 0

    # ─── Main Entry Point ─────────────────────────────────────

    async def run(self) -> dict:
        """
        Full agent lifecycle:
        1. Create agent_run record
        2. Check scope
        3. Execute scanning logic
        4. Create findings
        5. Update agent_run status
        Returns summary dict.
        """
        # Step 1: Create agent_run (short session)
        async with AsyncSessionLocal() as db:
            agent_run = AgentRun(
                scan_id=uuid.UUID(self.scan_id),
                agent_type=self.agent_type,
                agent_name=self.agent_name,
                status=AgentStatus.RUNNING,
                phase=self.phase,
                mitre_tags=self.mitre_tags,
                started_at=utc_now(),
            )
            db.add(agent_run)
            await db.commit()
            await db.refresh(agent_run)
            self.agent_run_id = str(agent_run.id)

        await self._broadcast("agent.status", {
            "agent_run_id": self.agent_run_id,
            "status": "running",
            "agent_type": self.agent_type,
            "agent_name": self.agent_name,
        })

        try:
            # Step 2: Scope check (short session)
            async with AsyncSessionLocal() as db:
                if not await self._check_scope(db):
                    await self._update_agent_run(AgentStatus.CANCELLED)
                    return {"status": "out_of_scope", "findings": 0}

            # Step 3: Execute — subclass does the work (NO open DB session)
            await self.report_progress(5, "Starting scan...")
            raw_findings = await self.execute()

            # Step 4: Save findings (short session)
            async with AsyncSessionLocal() as db:
                await self.report_progress(85, "Saving findings...")
                created = await self._create_findings(db, raw_findings)

            # Step 5: Update agent_run status (short session)
            await self._update_agent_run(
                AgentStatus.COMPLETED,
                findings_count=len(created),
            )

            await self.report_progress(100, "Complete")
            await self._broadcast("agent.status", {
                "agent_run_id": self.agent_run_id,
                "status": "completed",
                "findings_count": len(created),
            })
            return {"status": "completed", "findings": len(created)}

        except Exception as e:
            logger.error(f"Agent {self.agent_type} failed: {e}", exc_info=True)

            # Attempt self-correction
            async with AsyncSessionLocal() as db:
                corrected = await self._try_self_correct(db, {"error": str(e)})

            status = AgentStatus.COMPLETED if corrected else AgentStatus.ERROR
            await self._update_agent_run(
                status,
                retry_count=self.retry_count,
                last_log_line=None if corrected else str(e)[:500],
            )

            await self._broadcast("agent.status", {
                "agent_run_id": self.agent_run_id,
                "status": status.value,
                "error": str(e)[:200],
            })
            return {"status": status.value, "error": str(e)[:200]}

    async def _update_agent_run(
        self,
        status: AgentStatus,
        findings_count: int | None = None,
        retry_count: int | None = None,
        last_log_line: str | None = None,
    ) -> None:
        """Update agent_run record with short-lived session."""
        async with AsyncSessionLocal() as db:
            agent_run = await db.get(AgentRun, uuid.UUID(self.agent_run_id))
            if agent_run:
                agent_run.status = status
                agent_run.completed_at = utc_now()
                if agent_run.started_at:
                    agent_run.duration_seconds = int(
                        (agent_run.completed_at - agent_run.started_at).total_seconds()
                    )
                if findings_count is not None:
                    agent_run.findings_count = findings_count
                    agent_run.progress_pct = 100
                if retry_count is not None:
                    agent_run.retry_count = retry_count
                if last_log_line is not None:
                    agent_run.last_log_line = last_log_line
                await db.commit()

    # ─── Abstract: Subclass Must Implement ────────────────────

    @abstractmethod
    async def execute(self) -> list[dict]:
        """
        Run the actual scanning logic. Return a list of finding dicts:
        [
            {
                "finding_type": FindingType.SUBDOMAIN,
                "severity": FindingSeverity.INFO,
                "value": "api.target.com",
                "detail": "Discovered via crt.sh certificate transparency",
                "mitre_technique_ids": ["T1593"],
                "raw_data": {"source": "crt.sh", "ip": "1.2.3.4"},
            },
            ...
        ]
        """
        ...

    # ─── Async Subprocess Execution ───────────────────────────

    async def run_command(
        self,
        cmd: list[str],
        timeout: int = 300,
        parse_json: bool = False,
        silent: bool = False,
    ) -> dict:
        """
        Execute an external tool via async subprocess.
        Amendment #10: NEVER use subprocess.run — it blocks the event loop.
        
        Args:
            cmd: Command and arguments
            timeout: Seconds before kill
            parse_json: Parse stdout as JSON/JSONL
            silent: Skip progress reporting (use for utility calls like dig)
        
        Returns:
            {"stdout": str, "stderr": str, "returncode": int, "parsed": list|None}
        """
        tool_name = cmd[0] if cmd else "unknown"
        if not silent:
            await self.report_progress(self._progress, f"Running {tool_name}...")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise TimeoutError(f"{tool_name} timed out after {timeout}s")

        result = {
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "returncode": proc.returncode,
            "parsed": None,
        }

        if parse_json and result["stdout"].strip():
            try:
                # Handle JSONL (one JSON object per line — common in Go tools)
                lines = result["stdout"].strip().split("\n")
                result["parsed"] = [json.loads(line) for line in lines if line.strip()]
            except json.JSONDecodeError:
                try:
                    result["parsed"] = json.loads(result["stdout"])
                except json.JSONDecodeError:
                    logger.warning(f"{tool_name} output is not valid JSON")

        return result

    # ─── Progress Reporting ───────────────────────────────────

    async def report_progress(self, pct: int, message: str = "") -> None:
        """Update progress and broadcast to WebSocket clients."""
        self._progress = min(pct, 100)

        if self.agent_run_id:
            async with AsyncSessionLocal() as db:
                agent_run = await db.get(AgentRun, uuid.UUID(self.agent_run_id))
                if agent_run:
                    agent_run.progress_pct = self._progress
                    agent_run.last_log_line = message
                    agent_run.current_tool = message.split("Running ")[-1].rstrip("...") if "Running" in message else None
                    await db.commit()

            await self._broadcast("agent.status", {
                "agent_run_id": self.agent_run_id,
                "status": "running",
                "progress_pct": self._progress,
                "last_log_line": message,
            })

    # ─── Scope Checking ──────────────────────────────────────

    async def _check_scope(self, db: AsyncSession) -> bool:
        """Verify the target is in scope before scanning."""
        result = await db.execute(
            text("SELECT is_in_scope(:project_id, :target)"),
            {"project_id": self.project_id, "target": self.target_value}
        )
        is_in = result.scalar()

        if not is_in:
            # Log scope violation
            violation = ScopeViolation(
                scan_id=uuid.UUID(self.scan_id),
                agent_run_id=uuid.UUID(self.agent_run_id) if self.agent_run_id else None,
                agent_type=self.agent_type,
                attempted_target=self.target_value,
                reason=f"Target '{self.target_value}' is not in scope for project {self.project_id}",
            )
            db.add(violation)
            await db.commit()

            logger.warning(f"Scope violation: {self.agent_type} tried to scan {self.target_value}")
            await self._create_health_event(
                db, HealthEventType.ESCALATE_USER,
                "Scope violation detected",
                f"Agent {self.agent_name} attempted to scan {self.target_value} which is out of scope.",
            )

        return bool(is_in)

    # ─── Finding Creation ─────────────────────────────────────

    async def _create_findings(self, db: AsyncSession, raw_findings: list[dict]) -> list[Finding]:
        """Create Finding records from the raw finding dicts returned by execute()."""
        created = []
        for f in raw_findings:
            finding = Finding(
                scan_id=uuid.UUID(self.scan_id),
                agent_run_id=uuid.UUID(self.agent_run_id),
                finding_type=f.get("finding_type", FindingType.OTHER),
                severity=f.get("severity", FindingSeverity.INFO),
                value=f.get("value", ""),
                detail=f.get("detail", ""),
                mitre_technique_ids=f.get("mitre_technique_ids", self.mitre_tags),
                mitre_tactic_ids=f.get("mitre_tactic_ids", []),
                raw_data=f.get("raw_data"),
                confidence=f.get("confidence"),
                fingerprint=f.get("fingerprint"),
                tags=f.get("tags", []),
            )
            db.add(finding)
            created.append(finding)

            # Broadcast each finding to WebSocket
            await self._broadcast("agent.finding", {
                "agent_run_id": self.agent_run_id,
                "finding_type": finding.finding_type.value,
                "severity": finding.severity.value,
                "value": finding.value,
                "mitre_technique_ids": finding.mitre_technique_ids,
            })

        await db.commit()
        return created

    # ─── Self-Correction ──────────────────────────────────────

    async def self_correct(self, error_context: dict) -> bool:
        """
        Override in subclasses to implement self-correction.
        Return True if correction succeeded and findings were produced.
        Default: no self-correction.
        """
        return False

    async def _try_self_correct(self, db: AsyncSession, error_context: dict) -> bool:
        """Attempt self-correction up to max_retries times."""
        while self.retry_count < self.max_retries:
            self.retry_count += 1

            await self._create_health_event(
                db, HealthEventType.SELF_CORRECTION,
                f"Self-correction attempt {self.retry_count}/{self.max_retries}",
                f"Error: {error_context.get('error', 'unknown')}. Attempting auto-fix.",
            )

            try:
                corrected = await self.self_correct(error_context)
                if corrected:
                    await self._create_health_event(
                        db, HealthEventType.CORRECTION_SUCCESS,
                        "Self-correction succeeded",
                        f"Agent recovered after {self.retry_count} attempt(s).",
                    )
                    return True
            except Exception as e:
                error_context["error"] = str(e)
                logger.warning(f"Self-correction attempt {self.retry_count} failed: {e}")

        # All retries exhausted — escalate to user
        await self._create_health_event(
            db, HealthEventType.ESCALATE_USER,
            "Self-correction failed — user action needed",
            f"Agent {self.agent_name} failed after {self.max_retries} correction attempts. "
            f"Last error: {error_context.get('error', 'unknown')}",
            user_options=["Retry with different config", "Skip this agent", "Abort scan"],
        )
        return False

    # ─── Health Events ────────────────────────────────────────

    async def _create_health_event(
        self,
        db: AsyncSession,
        event_type: HealthEventType,
        title: str,
        detail: str,
        raw_command: str | None = None,
        user_options: list[str] | None = None,
    ) -> None:
        """Create a health event and broadcast to WebSocket."""
        event = HealthEvent(
            agent_run_id=uuid.UUID(self.agent_run_id) if self.agent_run_id else uuid.uuid4(),
            scan_id=uuid.UUID(self.scan_id),
            event_type=event_type,
            title=title,
            detail=detail,
            raw_command=raw_command,
            user_options=user_options,
        )
        db.add(event)
        await db.commit()

        await self._broadcast("agent.health", {
            "agent_run_id": self.agent_run_id,
            "event_type": event_type.value,
            "title": title,
            "detail": detail,
        })

    # ─── WebSocket Broadcasting ───────────────────────────────

    async def _broadcast(self, event_type: str, data: dict) -> None:
        """Publish event to Redis for WebSocket broadcast."""
        try:
            await publish_scan_event(self.scan_id, {
                "event": event_type,
                "data": data,
            })
        except Exception:
            pass  # Broadcasting failures must never crash the agent
