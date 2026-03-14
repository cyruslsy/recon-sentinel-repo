"""
Recon Sentinel — LangGraph Scan Orchestrator
Replaces the simple Celery group dispatch with an intelligent state machine.

Graph: START → passive → gate_1 → [PAUSE] → active → gate_2 → [PAUSE] → replan → vuln → report → END

Amendments: #6 (re-plan), #16 (circuit breaker), #24 (cost guard), #25 (fallback allowlist), #26 (budget cap)
"""

import json
import uuid
import logging
from dataclasses import dataclass, field, asdict
from decimal import Decimal

from app.core.celery_app import celery_app
from app.core.tz import utc_now
from app.core.database import AsyncSessionLocal
from app.core.llm import llm_call, parse_llm_json, LLMUnavailableError
from app.core.redis import publish_scan_event
from app.models.models import Scan, ApprovalGate
from app.models.enums import ScanPhase, ScanStatus, ApprovalDecision

logger = logging.getLogger(__name__)

# Allowlist of valid agent types for re-plan decisions (Amendment #25)
ALLOWED_AGENT_TYPES = frozenset({
    "subdomain", "osint", "email_sec", "threat_intel", "cred_leak",
    "port_scan", "web_recon", "ssl_tls", "dir_file", "cloud",
    "js_analysis", "vuln", "subdomain_takeover", "badsecrets",
    "wayback", "waf", "github_dork",
})


# ═══════════════════════════════════════════════════════════════
# RECON STATE
# ═══════════════════════════════════════════════════════════════

@dataclass
class ReconState:
    scan_id: str
    target_value: str
    project_id: str
    profile: str = "full"
    current_phase: str = "passive"
    phase_history: list[str] = field(default_factory=list)
    passive_results: list[dict] = field(default_factory=list)   # summary only: [{agent, status, findings_count}]
    active_results: list[dict] = field(default_factory=list)    # summary only
    vuln_results: list[dict] = field(default_factory=list)      # summary only
    findings_summary: dict = field(default_factory=dict)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    # Discovered targets from passive phase — active agents fan out across these
    discovered_targets: list[str] = field(default_factory=list)
    gate_1_decision: str | None = None
    gate_1_modifications: dict | None = None
    gate_2_decision: str | None = None
    gate_2_modifications: dict | None = None
    planned_agents: list[str] = field(default_factory=list)
    replan_count: int = 0
    max_replan_iterations: int = 3
    replan_cost_usd: float = 0.0
    max_replan_cost_usd: float = 0.50
    replan_decisions: list[dict] = field(default_factory=list)
    previously_modified: set = field(default_factory=set)
    total_llm_cost_usd: float = 0.0
    started_at: str | None = None
    completed_at: str | None = None

    def to_json(self) -> dict:
        d = asdict(self)
        d["previously_modified"] = list(self.previously_modified)
        return d

    @classmethod
    def from_json(cls, data: dict) -> "ReconState":
        data = dict(data)
        data["previously_modified"] = set(
            tuple(x) if isinstance(x, list) else x
            for x in data.get("previously_modified", [])
        )
        valid = {k for k in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in valid})


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

class ScanOrchestrator:

    def __init__(self, state: ReconState):
        self.state = state

    async def run_from_phase(self, phase: str | None = None) -> ReconState:
        if phase:
            self.state.current_phase = phase

        # Global safety limits
        max_scan_duration_hours = 6
        max_total_findings = 10000
        # Use persisted started_at so resume doesn't reset the timeout clock
        from datetime import datetime, timezone
        if self.state.started_at:
            scan_start = datetime.fromisoformat(self.state.started_at)
            if scan_start.tzinfo is None:
                scan_start = scan_start.replace(tzinfo=timezone.utc)
        else:
            scan_start = utc_now()
            self.state.started_at = scan_start.isoformat()

        while self.state.current_phase != "done":
            # Check global timeout
            elapsed = (utc_now() - scan_start).total_seconds()
            if elapsed > max_scan_duration_hours * 3600:
                logger.error(f"Scan {self.state.scan_id} exceeded {max_scan_duration_hours}h global timeout")
                await self._update_scan(ScanPhase.DONE, ScanStatus.FAILED)
                self.state.current_phase = "done"
                break

            # Check findings cap
            if self.state.total_findings > max_total_findings:
                logger.error(f"Scan {self.state.scan_id} exceeded {max_total_findings} findings cap")
                await self._update_scan(ScanPhase.DONE, ScanStatus.COMPLETED)
                self.state.current_phase = "done"
                break

            current = self.state.current_phase
            self.state.phase_history.append(current)
            logger.info(f"Scan {self.state.scan_id}: phase '{current}'")

            if current == "passive":
                await self._run_passive()
                # Profile branching: passive_only stops after gate 1
                if self.state.profile == "passive_only":
                    self.state.current_phase = "report"
                    logger.info("passive_only profile — skipping active/vuln phases, generating report")
                elif self.state.profile == "bounty":
                    # Bounty: fire-and-forget — skip all gates, run everything automatically
                    self.state.current_phase = "active"
                    logger.info("bounty profile — auto-approving gates, full speed ahead")
                else:
                    self.state.current_phase = "gate_1"

            elif current == "gate_1":
                if self.state.profile == "bounty":
                    # Auto-approve gate 1 for bounty profile
                    self.state.gate_1_decision = "approved"
                    self.state.current_phase = "active"
                    logger.info("bounty profile — gate 1 auto-approved")
                else:
                    await self._generate_gate(1)
                    await self._save_checkpoint()
                    return self.state  # PAUSE for human

            elif current == "active":
                await self._run_active()
                # Profile branching: quick skips gate 2 and goes straight to vuln
                if self.state.profile in ("quick", "bounty"):
                    self.state.current_phase = "vuln"
                    logger.info(f"{self.state.profile} profile — skipping gate 2, proceeding to vuln")
                else:
                    self.state.current_phase = "gate_2"

            elif current == "gate_2":
                if self.state.profile == "bounty":
                    self.state.gate_2_decision = "approved"
                    self.state.current_phase = "replan"
                    logger.info("bounty profile — gate 2 auto-approved")
                else:
                    await self._generate_gate(2)
                    await self._save_checkpoint()
                    return self.state  # PAUSE for human

            elif current == "replan":
                await self._run_replan()
                self.state.current_phase = "vuln"

            elif current == "vuln":
                # Profile branching: stealth skips vuln phase entirely (no active probing)
                if self.state.profile == "stealth":
                    logger.info("stealth profile — skipping vulnerability scanning")
                else:
                    await self._run_vuln()
                self.state.current_phase = "report"

            elif current == "report":
                await self._generate_report()
                self.state.current_phase = "done"

            await self._save_checkpoint()

        self.state.completed_at = utc_now().isoformat()
        await self._update_scan(ScanPhase.DONE, ScanStatus.COMPLETED)
        await self._save_checkpoint()

        # Auto-diff: compare against previous scan of same target
        from app.tasks.diff import auto_diff_on_complete
        auto_diff_on_complete.delay(self.state.scan_id)

        await self._broadcast("scan.complete", {
            "total_findings": self.state.total_findings,
            "llm_cost_usd": self.state.total_llm_cost_usd,
        })

        # Notify configured channels
        try:
            from app.tasks.notifications import notify_scan_complete
            await notify_scan_complete(
                self.state.scan_id, self.state.project_id,
                self.state.total_findings, self.state.critical_count,
                self.state.target_value,
            )
        except Exception:
            pass

        return self.state

    async def handle_gate_decision(self, gate_number: int, decision: str, modifications: dict | None = None) -> ReconState:
        if gate_number == 1:
            self.state.gate_1_decision = decision
            self.state.gate_1_modifications = modifications
            self.state.current_phase = "done" if decision == "skipped" else "active"
        elif gate_number == 2:
            self.state.gate_2_decision = decision
            self.state.gate_2_modifications = modifications
            self.state.current_phase = "report" if decision == "skipped" else "replan"
        return await self.run_from_phase()

    # ─── Phases ───────────────────────────────────────────────

    async def _run_passive(self) -> None:
        await self._update_scan(ScanPhase.PASSIVE, ScanStatus.RUNNING)
        agents = [
            "app.agents.subdomain.run_subdomain_agent",
            "app.agents.osint.run_osint_agent",
            "app.agents.email_sec.run_email_sec_agent",
            "app.agents.threat_intel.run_threat_intel_agent",
            "app.agents.cred_leak.run_cred_leak_agent",
            "app.agents.wayback.run_wayback_agent",
            "app.agents.github_dork.run_github_dork_agent",
        ]
        raw = await self._dispatch_agents(agents)
        self.state.passive_results = self._summarize_results(raw)
        await self._refresh_findings_summary()

        # Collect discovered targets for active phase fan-out
        self.state.discovered_targets = await self._collect_discovered_targets()
        logger.info(
            f"Passive phase complete: {self.state.total_findings} findings, "
            f"{len(self.state.discovered_targets)} targets for active phase"
        )

    async def _run_active(self) -> None:
        """
        Fan-out: dispatch per-target agents across ALL discovered subdomains.
        
        Agent categories:
          - PER-TARGET: run once for each discovered subdomain/host
            (port_scan, web_recon, ssl_tls, dir_file, js_analysis)
          - DOMAIN-LEVEL: run once against root domain only
            (cloud — needs CNAME analysis across all subs, handled internally)
        """
        await self._update_scan(ScanPhase.ACTIVE)

        per_target_agents = [
            "app.agents.port_scan.run_port_scan_agent",
            "app.agents.web_recon.run_web_recon_agent",
            "app.agents.ssl_tls.run_ssl_tls_agent",
            "app.agents.dir_file.run_dir_file_agent",
            "app.agents.js_analysis.run_js_analysis_agent",
        ]

        domain_level_agents = [
            "app.agents.cloud.run_cloud_agent",
            "app.agents.waf.run_waf_agent",
        ]

        # Apply gate 1 modifications (user may skip certain agents)
        if self.state.gate_1_modifications:
            skip = self.state.gate_1_modifications.get("skip_agents", [])
            per_target_agents = [
                a for a in per_target_agents
                if a.split(".")[-1].replace("run_", "").replace("_agent", "") not in skip
            ]
            domain_level_agents = [
                a for a in domain_level_agents
                if a.split(".")[-1].replace("run_", "").replace("_agent", "") not in skip
            ]

        # Get targets to scan — discovered subdomains + root domain
        targets = self.state.discovered_targets or [self.state.target_value]

        # Cap fan-out to prevent resource exhaustion
        from app.core.config import get_settings
        _s = get_settings()
        max_targets = getattr(_s, "MAX_ACTIVE_TARGETS", 30)
        if len(targets) > max_targets:
            logger.warning(
                f"Capping active phase targets from {len(targets)} to {max_targets}. "
                f"Gate modifications or re-plan can adjust."
            )
            targets = targets[:max_targets]

        logger.info(f"Active phase: {len(per_target_agents)} agents × {len(targets)} targets + {len(domain_level_agents)} domain-level")

        # Dispatch per-target agents across all targets
        all_results = []

        # Fan-out: each target gets its own set of agent tasks
        all_results.extend(
            await self._dispatch_agents_fanout(per_target_agents, targets)
        )

        # Domain-level agents run once against root domain
        all_results.extend(
            await self._dispatch_agents(domain_level_agents)
        )

        self.state.active_results = self._summarize_results(all_results)
        await self._refresh_findings_summary()

    async def _run_vuln(self) -> None:
        await self._update_scan(ScanPhase.VULN)
        agents = [
            "app.agents.vuln.run_vuln_agent",
            "app.agents.subdomain_takeover.run_subdomain_takeover_agent",
            "app.agents.badsecrets.run_badsecrets_agent",
        ]

        # Apply re-plan modifications (may have added/skipped agents)
        for decision in self.state.replan_decisions:
            action = decision.get("action", "")
            agent_type = decision.get("agent_type", "")
            if action == "ADD_AGENT" and agent_type:
                if agent_type not in ALLOWED_AGENT_TYPES:
                    logger.warning(f"Replan requested unknown agent '{agent_type}' — blocked by allowlist")
                    continue
                task_name = f"app.agents.{agent_type}.run_{agent_type}_agent"
                if task_name not in agents:
                    agents.append(task_name)
            elif action == "SKIP_AGENT" and "vuln" in agent_type:
                agents = [a for a in agents if agent_type not in a]

        raw = await self._dispatch_agents(agents)
        self.state.vuln_results = self._summarize_results(raw)
        await self._refresh_findings_summary()

    async def _generate_report(self) -> None:
        """Generate scan report: create Report record, dispatch LLM generation."""
        await self._update_scan(ScanPhase.REPORT)

        async with AsyncSessionLocal() as db:
            from app.models.models import Report
            report = Report(
                scan_id=uuid.UUID(self.state.scan_id),
                report_title=f"Recon Report — {self.state.target_value}",
                file_path="pending",
                generated_by=uuid.UUID("00000000-0000-0000-0000-000000000000"),  # system
            )
            db.add(report)
            await db.commit()
            await db.refresh(report)
            report_id = str(report.id)

        # Dispatch async report generation (LLM executive summary)
        from app.tasks.reports import generate_report
        generate_report.delay(report_id)
        logger.info(f"Report generation dispatched for scan {self.state.scan_id}, report {report_id}")

    # ─── Gate Generation ──────────────────────────────────────

    async def _generate_gate(self, gate_number: int) -> None:
        phase_name = "passive" if gate_number == 1 else "active"
        await self._update_scan(
            ScanPhase.GATE_1 if gate_number == 1 else ScanPhase.GATE_2,
            ScanStatus.PAUSED,
        )

        summary = self.state.findings_summary
        targets_info = ""
        if gate_number == 1 and self.state.discovered_targets:
            targets_info = (
                f"\nDiscovered targets for active phase: {len(self.state.discovered_targets)} "
                f"(will fan out 5 agents across each).\n"
                f"Sample targets: {', '.join(self.state.discovered_targets[:10])}"
            )

        prompt = (
            f"You are a security scan orchestrator. Summarize {phase_name} phase results.\n"
            f"Target: {self.state.target_value}\n"
            f"Findings: {self.state.total_findings} total, {self.state.critical_count} critical, {self.state.high_count} high\n"
            f"Subdomains: {summary.get('subdomain_count', 0)}, Ports: {summary.get('port_count', 0)}"
            f"{targets_info}\n\n"
            f"Respond with JSON: {{\"summary\": \"...\", \"risk_assessment\": \"...\", "
            f"\"recommendation\": \"...\", \"suggested_scope\": []}}"
        )

        try:
            result = await llm_call(
                messages=[{"role": "user", "content": prompt}],
                model_tier="analysis",
                task_type="gate_analysis",
                scan_id=self.state.scan_id,
                response_format="json",
            )
            self.state.total_llm_cost_usd += float(result["cost_usd"])
            recommendation = parse_llm_json(result["content"])
        except Exception as e:
            logger.error(f"Gate {gate_number} analysis failed: {e}")
            recommendation = {
                "summary": f"{self.state.total_findings} findings from {phase_name} phase. Automated analysis unavailable.",
                "risk_assessment": "Manual review recommended.",
                "recommendation": "Proceed with default scope.",
                "suggested_scope": [],
            }

        async with AsyncSessionLocal() as db:
            gate = ApprovalGate(
                scan_id=uuid.UUID(self.state.scan_id),
                gate_number=gate_number,
                ai_summary=recommendation.get("summary", ""),
                ai_recommendation=recommendation,
                decision=ApprovalDecision.PENDING,
            )
            db.add(gate)
            await db.commit()

        await self._broadcast("scan.gate", {
            "gate_number": gate_number,
            "ai_summary": recommendation.get("summary", ""),
            "recommendation": recommendation,
        })

        # Notify configured channels
        try:
            from app.tasks.notifications import notify_gate_ready
            await notify_gate_ready(
                self.state.scan_id, self.state.project_id,
                gate_number, recommendation.get("summary", ""),
            )
        except Exception:
            pass

    # ─── Re-Plan (Amendments #6, #16, #24) ────────────────────

    async def _run_replan(self) -> None:
        if self.state.replan_count >= self.state.max_replan_iterations:
            logger.info("Re-plan: iteration limit reached")
            return
        if self.state.replan_cost_usd >= self.state.max_replan_cost_usd:
            logger.info(f"Re-plan: cost limit reached (${self.state.replan_cost_usd:.3f})")
            return

        prompt = (
            f"Current agents: {self.state.planned_agents or ['nuclei_default']}\n"
            f"Findings: {self.state.total_findings} total, {self.state.critical_count} critical\n"
            f"Technologies: {self.state.findings_summary.get('tech_detected', [])}\n\n"
            f"Should the plan change? Respond with JSON: "
            f"{{\"action\": \"NO_CHANGE|ADD_AGENT|MODIFY_AGENT|SKIP_AGENT\", "
            f"\"agent_type\": \"name_if_applicable\", \"reason\": \"brief\"}}"
        )

        try:
            result = await llm_call(
                messages=[{"role": "user", "content": prompt}],
                model_tier="routing",
                task_type="replan",
                scan_id=self.state.scan_id,
                response_format="json",
            )
            decision = parse_llm_json(result["content"])
            cost = float(result["cost_usd"])
            self.state.replan_count += 1
            self.state.replan_cost_usd += cost
            self.state.total_llm_cost_usd += cost

            action = decision.get("action", "NO_CHANGE")
            agent_type = decision.get("agent_type", "")
            action_key = f"{action}:{agent_type}"

            if action_key in self.state.previously_modified:
                logger.info(f"Re-plan dedup: rejecting {action_key}")
                action = "NO_CHANGE"
            else:
                self.state.previously_modified.add(action_key)

            if action == "ADD_AGENT" and agent_type:
                self.state.planned_agents.append(agent_type)
            elif action == "SKIP_AGENT" and agent_type:
                self.state.planned_agents = [a for a in self.state.planned_agents if a != agent_type]

            self.state.replan_decisions.append({
                **decision, "cost_usd": cost, "timestamp": utc_now().isoformat(),
            })

        except LLMUnavailableError:
            logger.warning("Re-plan LLM unavailable — proceeding with current plan")
        except Exception as e:
            logger.error(f"Re-plan failed: {e}")

    # ─── Agent Dispatch ───────────────────────────────────────

    async def _dispatch_agents(self, task_names: list[str]) -> list[dict]:
        """Dispatch agents against the root target."""
        import asyncio
        from celery import group
        tasks = group(
            celery_app.send_task(name, args=[
                self.state.scan_id, self.state.target_value, self.state.project_id, {}
            ])
            for name in task_names
        )
        try:
            result = tasks.apply_async()
            return await self._poll_result(result, timeout=600)
        except Exception as e:
            logger.error(f"Agent dispatch failed: {e}")
            return []

    async def _dispatch_agents_fanout(self, task_names: list[str], targets: list[str]) -> list[dict]:
        """
        Fan-out: dispatch each agent for each target in chunks.
        Chunks tasks to avoid overwhelming Celery workers.
        E.g., 5 agents × 20 subdomains = 100 tasks, dispatched in chunks of 20.
        """
        import asyncio
        from celery import group

        if not task_names or not targets:
            return []

        # Build all task signatures
        all_task_sigs = [
            celery_app.send_task(agent_name, args=[
                self.state.scan_id, target, self.state.project_id, {}
            ])
            for target in targets
            for agent_name in task_names
        ]

        total = len(all_task_sigs)
        chunk_size = 20  # Max concurrent tasks per chunk
        logger.info(f"Fan-out: {total} tasks in chunks of {chunk_size}")

        all_results = []
        for i in range(0, total, chunk_size):
            chunk = all_task_sigs[i:i + chunk_size]
            chunk_group = group(chunk)

            try:
                result = chunk_group.apply_async()
                chunk_results = await self._poll_result(result, timeout=600)
                all_results.extend(chunk_results)
                logger.info(f"Fan-out chunk {i // chunk_size + 1}: {len(chunk)} tasks completed")
            except Exception as e:
                logger.error(f"Fan-out chunk {i // chunk_size + 1} failed: {e}")

        return all_results

    async def _poll_result(self, result, timeout: int = 600) -> list[dict]:
        """
        Poll a Celery GroupResult without blocking a thread pool thread.
        Checks result.ready() in an async loop instead of calling result.get().
        """
        import asyncio
        elapsed = 0
        poll_interval = 2  # seconds

        while elapsed < timeout:
            if result.ready():
                try:
                    results = result.get(timeout=5)  # Should be instant since ready()
                    return results if isinstance(results, list) else [results]
                except Exception as e:
                    logger.error(f"Result retrieval failed: {e}")
                    return []
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        logger.error(f"Task group timed out after {timeout}s")
        return []

    async def _collect_discovered_targets(self) -> list[str]:
        """
        After passive phase, collect all unique live subdomains/hosts for active phase.
        Returns clean hostnames (no protocol, no path, no trailing port unless non-standard).
        Includes resolved subdomains (not wildcards, not NXDOMAIN) + OSINT hosts.
        """
        from sqlalchemy import select
        from app.models.models import Finding

        targets = set()

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Finding.value, Finding.raw_data, Finding.tags)
                .where(Finding.scan_id == uuid.UUID(self.state.scan_id))
                .where(Finding.finding_type.in_(["subdomain", "osint"]))
            )

            for value, raw_data, tags in result.all():
                # Skip wildcard subdomains
                if tags and "wildcard" in tags:
                    continue
                # Skip NXDOMAIN (no resolved IPs)
                if raw_data and isinstance(raw_data, dict):
                    ips = raw_data.get("resolved_ips", [])
                    if isinstance(ips, list) and not ips:
                        continue

                clean = self._clean_target(value)
                if clean:
                    targets.add(clean)

        # Always include root target
        targets.add(self._clean_target(self.state.target_value) or self.state.target_value)
        return sorted(targets)

    @staticmethod
    def _clean_target(value: str) -> str | None:
        """
        Normalize a target value to a clean hostname.
        Blocks internal/private IPs from being fanned out to agents.
        """
        import ipaddress as _ipa

        clean = value.strip().lower()

        # Strip protocol
        if "://" in clean:
            clean = clean.split("://", 1)[-1]

        # Strip path and query string
        clean = clean.split("/")[0]
        clean = clean.split("?")[0]
        clean = clean.split("#")[0]

        # Strip port (agents will probe standard ports themselves)
        if ":" in clean:
            host_part = clean.rsplit(":", 1)[0]
            if host_part and ("." in host_part or host_part.replace(":", "").isdigit()):
                clean = host_part

        clean = clean.strip(".")

        if not clean or ("." not in clean and not clean.replace(".", "").isdigit()):
            return None

        # Block private/internal IPs from fan-out targets
        try:
            ip = _ipa.ip_address(clean)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return None
        except ValueError:
            pass  # Not an IP — hostname is fine

        return clean

    @staticmethod
    def _summarize_results(raw_results: list) -> list[dict]:
        """Cap result storage — keep only summary metadata, not raw agent output."""
        summaries = []
        for r in raw_results:
            if isinstance(r, dict):
                summaries.append({
                    "status": r.get("status", "unknown"),
                    "findings_count": r.get("findings_count", 0),
                    "agent_type": r.get("agent_type", ""),
                })
            else:
                summaries.append({"status": "completed", "raw_type": str(type(r).__name__)})
        return summaries[:100]  # Hard cap at 100 entries

    # ─── DB Helpers ───────────────────────────────────────────

    async def _refresh_findings_summary(self) -> None:
        from sqlalchemy import func, select
        from app.models.models import Finding

        async with AsyncSessionLocal() as db:
            sev_rows = await db.execute(
                select(Finding.severity, func.count(Finding.id))
                .where(Finding.scan_id == uuid.UUID(self.state.scan_id))
                .group_by(Finding.severity)
            )
            counts = {r[0].value: r[1] for r in sev_rows.all()}
            self.state.total_findings = sum(counts.values())
            self.state.critical_count = counts.get("critical", 0)
            self.state.high_count = counts.get("high", 0)

            type_rows = await db.execute(
                select(Finding.finding_type, func.count(Finding.id))
                .where(Finding.scan_id == uuid.UUID(self.state.scan_id))
                .group_by(Finding.finding_type)
            )
            type_counts = {r[0].value: r[1] for r in type_rows.all()}
            self.state.findings_summary = {
                "severity_counts": counts,
                "type_counts": type_counts,
                "subdomain_count": type_counts.get("subdomain", 0),
                "port_count": type_counts.get("port", 0),
                "tech_detected": [],
            }

    async def _save_checkpoint(self) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, uuid.UUID(self.state.scan_id))
            if scan:
                scan.langgraph_checkpoint = self.state.to_json()
                scan.total_findings = self.state.total_findings
                scan.critical_count = self.state.critical_count
                scan.high_count = self.state.high_count
                await db.commit()

    async def _update_scan(self, phase: ScanPhase, status: ScanStatus | None = None) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, uuid.UUID(self.state.scan_id))
            if scan:
                scan.phase = phase
                if status:
                    scan.status = status
                await db.commit()
        await self._broadcast("scan.phase", {"phase": phase.value, "status": status.value if status else None})

    async def _broadcast(self, event_type: str, data: dict) -> None:
        try:
            await publish_scan_event(self.state.scan_id, {"event": event_type, "data": data})
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# CELERY TASKS
# ═══════════════════════════════════════════════════════════════

@celery_app.task(name="app.tasks.orchestrator.start_scan")
def start_scan(scan_id: str, target_value: str, project_id: str, profile: str = "full"):
    import asyncio
    import signal as _signal
    from app.core.config import get_settings
    s = get_settings()
    state = ReconState(
        scan_id=scan_id, target_value=target_value, project_id=project_id,
        profile=profile, started_at=utc_now().isoformat(),
        max_replan_iterations=s.LLM_MAX_REPLAN_ITERATIONS,
        max_replan_cost_usd=s.LLM_MAX_REPLAN_COST_USD,
    )
    orchestrator = ScanOrchestrator(state)

    # Graceful shutdown: save checkpoint on SIGTERM before worker dies
    def _handle_sigterm(signum, frame):
        logger.warning(f"SIGTERM received during scan {scan_id} — saving checkpoint")
        try:
            asyncio.run(orchestrator._save_checkpoint())
        except Exception as e:
            logger.error(f"Failed to save checkpoint on SIGTERM: {e}")
        raise SystemExit(1)

    original_handler = _signal.getsignal(_signal.SIGTERM)
    _signal.signal(_signal.SIGTERM, _handle_sigterm)

    try:
        final = asyncio.run(orchestrator.run_from_phase("passive"))
        return {"status": final.current_phase, "findings": final.total_findings}
    finally:
        _signal.signal(_signal.SIGTERM, original_handler)


@celery_app.task(name="app.tasks.orchestrator.handle_gate_decision")
def handle_gate_decision(scan_id: str, gate_number: int, decision: str, modifications: dict | None = None):
    import asyncio
    async def _resume():
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, uuid.UUID(scan_id))
            if not scan or not scan.langgraph_checkpoint:
                raise ValueError(f"No checkpoint for scan {scan_id}")
            state = ReconState.from_json(scan.langgraph_checkpoint)
        orchestrator = ScanOrchestrator(state)
        return await orchestrator.handle_gate_decision(gate_number, decision, modifications)
    final = asyncio.run(_resume())
    return {"status": final.current_phase, "findings": final.total_findings}


@celery_app.task(name="app.tasks.orchestrator.start_active_phase")
def start_active_phase(scan_id: str, target_value: str, project_id: str):
    return handle_gate_decision(scan_id, 1, "approved")


@celery_app.task(name="app.tasks.orchestrator.resume_scan_from_checkpoint")
def resume_scan_from_checkpoint(scan_id: str):
    """Resume a scan from its saved checkpoint. Used by POST /scans/{id}/resume."""
    import asyncio

    async def _resume():
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, uuid.UUID(scan_id))
            if not scan or not scan.langgraph_checkpoint:
                raise ValueError(f"No checkpoint for scan {scan_id}")
            state = ReconState.from_json(scan.langgraph_checkpoint)

        logger.info(f"Resuming scan {scan_id} from phase: {state.current_phase}")
        orchestrator = ScanOrchestrator(state)
        return await orchestrator.run_from_phase()

    final = asyncio.run(_resume())
    return {"status": final.current_phase, "findings": final.total_findings}
