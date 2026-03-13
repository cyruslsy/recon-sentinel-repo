"""
Recon Sentinel — Report Generation Task
Uses Claude Sonnet to generate executive summaries and structured reports.
Outputs PDF, HTML, or JSON based on report format setting.

PDF rendering uses reportlab (Platypus) for professional pentest-quality reports.
HTML rendering produces a self-contained styled HTML file.
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

# Severity color mapping for reports
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}


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
        report_format = report.format

    # Step 2: Build summaries (no DB needed)
    severity_counts = {}
    finding_summaries = []
    findings_data = []
    for f in findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        findings_data.append({
            "id": str(f.id),
            "type": f.finding_type.value,
            "severity": sev,
            "value": f.value,
            "detail": f.detail,
            "mitre_techniques": f.mitre_technique_ids,
            "tags": f.tags,
        })
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

    # Step 4: Build report data
    report_data = {
        "title": report_title or f"Recon Report — {target_value}",
        "target": target_value,
        "scan_id": scan_id_str,
        "generated_at": utc_now().isoformat(),
        "executive_summary": executive_summary,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "findings": findings_data,
    }

    # Step 5: Render in requested format
    try:
        report_dir = "/data/reports"
        import os
        os.makedirs(report_dir, exist_ok=True)
    except OSError:
        report_dir = "/tmp"

    if report_format == ReportFormat.PDF:
        report_path = f"{report_dir}/{report_id}.pdf"
        _render_pdf(report_data, report_path)
    elif report_format == ReportFormat.HTML:
        report_path = f"{report_dir}/{report_id}.html"
        _render_html(report_data, report_path)
    else:
        # Default: JSON
        report_path = f"{report_dir}/{report_id}.json"
        with open(report_path, "w") as fp:
            json.dump(report_data, fp, indent=2, default=str)

    # Step 6: Update DB record (short session)
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

    logger.info(f"Report {report_id} generated ({report_format.value}): {len(findings)} findings → {report_path}")
    return {"status": "completed", "path": report_path, "format": report_format.value, "findings": len(findings)}


# ─── PDF Rendering ──────────────────────────────────────────────

def _render_pdf(data: dict, output_path: str) -> None:
    """Render a professional pentest PDF report using reportlab."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    doc = SimpleDocTemplate(output_path, pagesize=letter,
                            topMargin=0.75*inch, bottomMargin=0.75*inch,
                            leftMargin=0.75*inch, rightMargin=0.75*inch)
    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=22,
                              textColor=HexColor("#1e293b"), spaceAfter=6))
    styles.add(ParagraphStyle("SectionHead", parent=styles["Heading1"], fontSize=14,
                              textColor=HexColor("#0f172a"), spaceBefore=18, spaceAfter=8))
    styles.add(ParagraphStyle("BodyText", parent=styles["Normal"], fontSize=10,
                              leading=14, textColor=HexColor("#334155")))
    styles.add(ParagraphStyle("FindingTitle", parent=styles["Normal"], fontSize=10,
                              textColor=HexColor("#1e293b"), fontName="Helvetica-Bold"))

    story = []

    # ─── Cover / Header ─────────────────────────────────────
    story.append(Paragraph(data["title"], styles["ReportTitle"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Target: {data['target']}", styles["BodyText"]))
    story.append(Paragraph(f"Generated: {data['generated_at'][:19].replace('T', ' ')}", styles["BodyText"]))
    story.append(Paragraph(f"Total findings: {data['total_findings']}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    # ─── Severity Summary Table ─────────────────────────────
    story.append(Paragraph("Severity Summary", styles["SectionHead"]))
    sev_data = [["Severity", "Count"]]
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = data["severity_counts"].get(sev, 0)
        if count > 0:
            sev_data.append([sev.upper(), str(count)])

    if len(sev_data) > 1:
        sev_table = Table(sev_data, colWidths=[2*inch, 1.5*inch])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#f8fafc"), HexColor("#ffffff")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(sev_table)
    story.append(Spacer(1, 16))

    # ─── Executive Summary ──────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["SectionHead"]))
    for para in data["executive_summary"].split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), styles["BodyText"]))
            story.append(Spacer(1, 6))
    story.append(PageBreak())

    # ─── Findings ───────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", styles["SectionHead"]))

    for i, f in enumerate(data["findings"][:100]):  # Cap at 100 for PDF size
        sev = f["severity"]
        color = SEVERITY_COLORS.get(sev, "#6b7280")

        story.append(Paragraph(
            f'<font color="{color}">[{sev.upper()}]</font> {f["value"][:120]}',
            styles["FindingTitle"],
        ))
        if f.get("detail"):
            story.append(Paragraph(f["detail"][:300], styles["BodyText"]))
        if f.get("mitre_techniques"):
            story.append(Paragraph(
                f'<font color="#6b7280">MITRE: {", ".join(f["mitre_techniques"])}</font>',
                styles["BodyText"],
            ))
        story.append(Spacer(1, 8))

    if len(data["findings"]) > 100:
        story.append(Paragraph(
            f'<font color="#6b7280">... and {len(data["findings"]) - 100} more findings (see full JSON export)</font>',
            styles["BodyText"],
        ))

    doc.build(story)
    logger.info(f"PDF report rendered: {output_path}")


# ─── HTML Rendering ─────────────────────────────────────────────

def _render_html(data: dict, output_path: str) -> None:
    """Render a self-contained HTML report with inline CSS."""
    findings_html = ""
    for f in data["findings"]:
        sev = f["severity"]
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        mitre = ", ".join(f.get("mitre_techniques", []))
        detail_escaped = (f.get("detail") or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        value_escaped = (f.get("value") or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity" style="background:{color}">{sev.upper()}</span>
                <span class="finding-value">{value_escaped[:150]}</span>
            </div>
            <p class="finding-detail">{detail_escaped[:500]}</p>
            {"<p class='mitre'>MITRE: " + mitre + "</p>" if mitre else ""}
        </div>"""

    sev_rows = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = data["severity_counts"].get(sev, 0)
        if count:
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            sev_rows += f'<tr><td><span class="severity" style="background:{color}">{sev.upper()}</span></td><td>{count}</td></tr>'

    exec_summary = data["executive_summary"].replace("\n\n", "</p><p>").replace("\n", "<br>")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{data["title"]}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 40px 20px; color: #1e293b; background: #f8fafc; }}
h1 {{ font-size: 24px; border-bottom: 3px solid #1e293b; padding-bottom: 8px; }}
h2 {{ font-size: 18px; color: #0f172a; margin-top: 32px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }}
.meta {{ color: #64748b; font-size: 14px; margin-bottom: 24px; }}
.severity {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
table {{ border-collapse: collapse; margin: 12px 0; }}
th, td {{ padding: 8px 16px; text-align: left; border: 1px solid #e2e8f0; }}
th {{ background: #1e293b; color: white; }}
tr:nth-child(even) {{ background: #f1f5f9; }}
.finding {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; }}
.finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
.finding-value {{ font-weight: 600; font-size: 14px; }}
.finding-detail {{ color: #475569; font-size: 13px; margin: 4px 0; }}
.mitre {{ color: #6b7280; font-size: 12px; }}
p {{ line-height: 1.6; }}
</style>
</head>
<body>
<h1>{data["title"]}</h1>
<div class="meta">Target: {data["target"]} | Generated: {data["generated_at"][:19].replace("T", " ")} | Findings: {data["total_findings"]}</div>

<h2>Severity Summary</h2>
<table><tr><th>Severity</th><th>Count</th></tr>{sev_rows}</table>

<h2>Executive Summary</h2>
<p>{exec_summary}</p>

<h2>Findings ({data["total_findings"]})</h2>
{findings_html}
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    logger.info(f"HTML report rendered: {output_path}")
