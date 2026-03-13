"""
Recon Sentinel — Report Generation Task
Uses Claude Sonnet to generate executive summaries and structured reports.
Outputs JSON report data (PDF/DOCX rendering is a future enhancement).
"""

import uuid
import json
import logging

from sqlalchemy import select, func

from app.core.celery_app import celery_app
from app.core.tz import utc_now
from app.core.database import AsyncSessionLocal
from app.core.llm import llm_call, LLMUnavailableError
from app.models.models import Report, Scan, Finding, Target
from app.models.enums import FindingSeverity, ReportFormat

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.reports.generate_report")
def generate_report(report_id: str):
    """Celery task: generate a scan report with AI executive summary."""
    import asyncio
    return asyncio.run(_generate_report(report_id))


async def _generate_report(report_id: str) -> dict:
    # Step 1: Load data (short session)
    async with AsyncSessionLocal() as db:
        report = await db.get(Report, uuid.UUID(report_id))
        if not report:
            raise ValueError(f"Report {report_id} not found")

        scan = await db.get(Scan, report.scan_id)
        if not scan:
            raise ValueError(f"Scan {report.scan_id} not found")

        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan.id, Finding.is_false_positive == False)  # noqa
            .order_by(Finding.severity, Finding.created_at)
        )
        findings = result.scalars().all()

        target = await db.get(Target, scan.target_id)
        target_value = target.target_value if target else "unknown"
        scan_profile = scan.profile.value
        scan_id_str = str(scan.id)
        report_title = report.report_title

    # Step 2: Build summaries (no DB needed)
    severity_counts = {}
    finding_summaries = []
    for f in findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if len(finding_summaries) < 30:
            finding_summaries.append({
                "type": f.finding_type.value,
                "severity": sev,
                "value": f.value[:100],
                "detail": f.detail[:150],
                "mitre": f.mitre_technique_ids,
            })

    # Step 3: LLM call (no open DB session — can take 10-30s)
    prompt = (
        f"You are a senior penetration tester writing an executive summary for a recon scan report.\n\n"
        f"Target: {target_value}\n"
        f"Scan profile: {scan_profile}\n"
        f"Total findings: {len(findings)}\n"
        f"Severity breakdown: {json.dumps(severity_counts)}\n\n"
        f"Top findings:\n{json.dumps(finding_summaries[:15], indent=2)}\n\n"
        f"Write a professional executive summary (3-4 paragraphs) covering:\n"
        f"1. Scope and methodology\n"
        f"2. Key findings and risk assessment\n"
        f"3. Critical/high severity items requiring immediate attention\n"
        f"4. Recommendations for remediation priority\n\n"
        f"Write in a professional tone suitable for C-level stakeholders."
    )

    llm_model = None
    llm_tokens = None
    llm_cost = None

    try:
        llm_result = await llm_call(
            messages=[{"role": "user", "content": prompt}],
            model_tier="analysis",
            task_type="report",
            scan_id=scan_id_str,
            max_tokens=2000,
        )
        executive_summary = llm_result["content"]
        llm_model = llm_result["model"]
        llm_tokens = llm_result["tokens_in"] + llm_result["tokens_out"]
        llm_cost = llm_result["cost_usd"]
    except LLMUnavailableError:
        executive_summary = (
            f"Automated executive summary unavailable. "
            f"Scan of {target_value} produced {len(findings)} findings: "
            f"{severity_counts.get('critical', 0)} critical, "
            f"{severity_counts.get('high', 0)} high, "
            f"{severity_counts.get('medium', 0)} medium."
        )

    # Step 4: Build and save report (short session)
    report_data = {
        "title": report_title or f"Recon Report — {target_value}",
        "target": target_value,
        "scan_id": scan_id_str,
        "generated_at": utc_now().isoformat(),
        "executive_summary": executive_summary,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "findings": [
            {
                "id": str(f.id),
                "type": f.finding_type.value,
                "severity": f.severity.value,
                "value": f.value,
                "detail": f.detail,
                "mitre_techniques": f.mitre_technique_ids,
                "tags": f.tags,
            }
            for f in findings
        ],
    }

    report_path = f"/data/reports/{report_id}.json"
    try:
        with open(report_path, "w") as fp:
            json.dump(report_data, fp, indent=2, default=str)
    except OSError:
        report_path = f"/tmp/report_{report_id}.json"
        with open(report_path, "w") as fp:
            json.dump(report_data, fp, indent=2, default=str)

    # Step 5: Update DB record (short session)
    async with AsyncSessionLocal() as db:
        report = await db.get(Report, uuid.UUID(report_id))
        if report:
            report.ai_executive_summary = executive_summary
            report.file_path = report_path
            report.generated_at = utc_now()
            report.ai_model_used = llm_model
            report.ai_tokens_used = llm_tokens
            report.ai_cost_usd = llm_cost
            await db.commit()

    logger.info(f"Report {report_id} generated: {len(findings)} findings, saved to {report_path}")
    return {"status": "completed", "path": report_path, "findings": len(findings)}
