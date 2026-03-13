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
from datetime import datetime
from decimal import Decimal

from app.core.celery_app import celery_app
from app.core.tz import utc_now
from app.core.database import AsyncSessionLocal
from app.core.tz import utc_now
from app.core.llm import llm_call, parse_llm_json, LLMUnavailableError
from app.core.tz import utc_now
from app.core.redis import publish_scan_event
from app.core.tz import utc_now
from app.models.models import Scan, ApprovalGate
from app.core.tz import utc_now
from app.models.enums import ScanPhase, ScanStatus, ApprovalDecision
from app.core.tz import utc_now

logger = logging.getLogger(__name__)


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
    passive_results: list[dict] = field(default_factory=list)
    active_results: list[dict] = field(default_factory=list)
    vuln_results: list[dict] = field(default_factory=list)
    findings_summary: dict = field(default_factory=dict)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
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

        while self.state.current_phase != "done":
            current = self.state.current_phase
            self.state.phase_history.append(current)
            logger.info(f"Scan {self.state.scan_id}: phase '{current}'")

            if current == "passive":
                await self._run_passive()
                self.state.current_phase = "gate_1"

            elif current == "gate_1":
                await self._generate_gate(1)
                await self._save_checkpoint()
                return self.state  # PAUSE for human

            elif current == "active":
                await self._run_active()
                self.state.current_phase = "gate_2"

            elif current == "gate_2":
                await self._generate_gate(2)
                await self._save_checkpoint()
                return self.state  # PAUSE for human

            elif current == "replan":
                await self._run_replan()
                self.state.current_phase = "vuln"

            elif current == "vuln":
                await self._run_vuln()
                self.state.current_phase = "report"

            elif current == "report":
                await self._generate_report()
                self.state.current_phase = "done"

            await self._save_checkpoint()

        self.state.completed_at = utc_now().isoformat()
        await self._update_scan(ScanPhase.DONE, ScanStatus.COMPLETED)
        await self._save_checkpoint()
        await self._broadcast("scan.complete", {
            "total_findings": self.state.total_findings,
            "llm_cost_usd": self.state.total_llm_cost_usd,
        })
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
        ]
        self.state.passive_results = await self._dispatch_agents(agents)
        await self._refresh_findings_summary()

    async def _run_active(self) -> None:
        await self._update_scan(ScanPhase.ACTIVE)
        agents = [
            "app.agents.port_scan.run_port_scan_agent",
            "app.agents.web_recon.run_web_recon_agent",
            "app.agents.ssl_tls.run_ssl_tls_agent",
            "app.agents.dir_file.run_dir_file_agent",
            "app.agents.cloud.run_cloud_agent",
            "app.agents.js_analysis.run_js_analysis_agent",
        ]
        if self.state.gate_1_modifications:
            skip = self.state.gate_1_modifications.get("skip_agents", [])
            agents = [a for a in agents if a.split(".")[-1].replace("run_", "").replace("_agent", "") not in skip]
        self.state.active_results = await self._dispatch_agents(agents)
        await self._refresh_findings_summary()

    async def _run_vuln(self) -> None:
        await self._update_scan(ScanPhase.VULN)
        agents = [
            "app.agents.vuln.run_vuln_agent",
            "app.agents.subdomain_takeover.run_subdomain_takeover_agent",
        ]

        # Apply re-plan modifications (may have added/skipped agents)
        for decision in self.state.replan_decisions:
            action = decision.get("action", "")
            agent_type = decision.get("agent_type", "")
            if action == "ADD_AGENT" and agent_type:
                agents.append(f"app.agents.{agent_type}.run_{agent_type}_agent")
            elif action == "SKIP_AGENT" and "vuln" in agent_type:
                agents = [a for a in agents if agent_type not in a]

        self.state.vuln_results = await self._dispatch_agents(agents)
        await self._refresh_findings_summary()

    async def _generate_report(self) -> None:
        await self._update_scan(ScanPhase.REPORT)
        # TODO: Week 6 — Sonnet report generation
        logger.info(f"Report generation placeholder for scan {self.state.scan_id}")

    # ─── Gate Generation ──────────────────────────────────────

    async def _generate_gate(self, gate_number: int) -> None:
        phase_name = "passive" if gate_number == 1 else "active"
        await self._update_scan(
            ScanPhase.GATE_1 if gate_number == 1 else ScanPhase.GATE_2,
            ScanStatus.PAUSED,
        )

        summary = self.state.findings_summary
        prompt = (
            f"You are a security scan orchestrator. Summarize {phase_name} phase results.\n"
            f"Target: {self.state.target_value}\n"
            f"Findings: {self.state.total_findings} total, {self.state.critical_count} critical, {self.state.high_count} high\n"
            f"Subdomains: {summary.get('subdomain_count', 0)}, Ports: {summary.get('port_count', 0)}\n\n"
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
            # result.get() is synchronous/blocking — run in thread to avoid blocking event loop
            results = await asyncio.to_thread(result.get, timeout=600)
            return results if isinstance(results, list) else [results]
        except Exception as e:
            logger.error(f"Agent dispatch failed: {e}")
            return []

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
    from app.core.config import get_settings
    s = get_settings()
    state = ReconState(
        scan_id=scan_id, target_value=target_value, project_id=project_id,
        profile=profile, started_at=utc_now().isoformat(),
        max_replan_iterations=s.LLM_MAX_REPLAN_ITERATIONS,
        max_replan_cost_usd=s.LLM_MAX_REPLAN_COST_USD,
    )
    orchestrator = ScanOrchestrator(state)
    final = asyncio.run(orchestrator.run_from_phase("passive"))
    return {"status": final.current_phase, "findings": final.total_findings}


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
