"""
Recon Sentinel — Notification Engine
Dispatches alerts to configured channels (Slack, Discord, Telegram, email, webhook).
Fires in real-time when:
  - Critical/high finding discovered
  - Credential leak with passwords found
  - Subdomain takeover confirmed
  - Approval gate ready
  - Scan completed
  - Agent error requiring attention

Channel config stored in notification_channels.config (JSONB):
  Slack:    {"webhook_url": "https://hooks.slack.com/services/..."}
  Discord:  {"webhook_url": "https://discord.com/api/webhooks/..."}
  Telegram: {"bot_token": "...", "chat_id": "..."}
  Email:    {"smtp_host": "...", "smtp_port": 587, "to": ["admin@..."], "from": "sentinel@..."}
  Webhook:  {"url": "https://...", "headers": {"X-Auth": "..."}, "method": "POST"}
"""

import ipaddress
import json
import logging
import uuid
from urllib.parse import urlparse

import httpx

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.core.tz import utc_now
from app.models.models import NotificationChannelModel, NotificationLog, Finding
from app.models.enums import NotificationEvent, NotificationChannel, FindingSeverity

logger = logging.getLogger(__name__)


# ─── SSRF Protection ─────────────────────────────────────────

def _is_safe_url(url: str) -> tuple[bool, str]:
    """
    Validate a webhook URL is not targeting internal/private infrastructure.
    Blocks: private IPs, localhost, link-local, cloud metadata, non-http schemes.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"

    # Must be http or https
    if parsed.scheme not in ("http", "https"):
        return False, f"Blocked scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname"

    # Block obvious internal hostnames
    blocked_hosts = {
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "metadata.google.internal", "metadata.google.com",
        "169.254.169.254",  # AWS/GCP metadata
        "100.100.100.200",  # Alibaba metadata
    }
    if hostname.lower() in blocked_hosts:
        return False, f"Blocked host: {hostname}"

    # Block private/reserved IP ranges
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, f"Blocked private/reserved IP: {hostname}"
    except ValueError:
        # Not an IP — it's a hostname, which is fine
        # But block .internal and .local TLDs
        if hostname.endswith(".internal") or hostname.endswith(".local"):
            return False, f"Blocked internal hostname: {hostname}"

    return True, ""


# ─── Main Dispatch ────────────────────────────────────────────

@celery_app.task(name="app.tasks.notifications.dispatch_notification")
def dispatch_notification(event_type: str, project_id: str, scan_id: str | None = None, payload: dict | None = None):
    """Celery task: find matching channels and send notifications."""
    import asyncio
    return asyncio.run(_dispatch(event_type, project_id, scan_id, payload or {}))


async def _dispatch(event_type: str, project_id: str, scan_id: str | None, payload: dict) -> dict:
    """Find all enabled channels subscribed to this event and send."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(NotificationChannelModel).where(
                NotificationChannelModel.project_id == uuid.UUID(project_id),
                NotificationChannelModel.is_enabled == True,  # noqa
            )
        )
        channels = result.scalars().all()

    sent = 0
    failed = 0

    # Reuse one HTTP client for all channel sends in this dispatch
    async with httpx.AsyncClient(timeout=10) as http_client:
        for channel in channels:
            if channel.subscribed_events and event_type not in channel.subscribed_events:
                continue

            success, error = await _send_to_channel(channel, event_type, payload, http_client)

            async with AsyncSessionLocal() as db:
                log = NotificationLog(
                    channel_id=channel.id,
                    event_type=event_type,
                    scan_id=uuid.UUID(scan_id) if scan_id else None,
                    payload=payload,
                    status="sent" if success else "failed",
                    error_message=error,
                    sent_at=utc_now() if success else None,
                )
                db.add(log)
                await db.commit()

            if success:
                sent += 1
            else:
                failed += 1

    logger.info(f"Notification '{event_type}': {sent} sent, {failed} failed")
    return {"event": event_type, "sent": sent, "failed": failed}


# ─── Channel Senders ─────────────────────────────────────────

async def _send_to_channel(channel: NotificationChannelModel, event_type: str, payload: dict, http_client: httpx.AsyncClient) -> tuple[bool, str | None]:
    """Route to the correct sender based on channel type."""
    try:
        config = channel.config or {}

        if channel.channel_type == NotificationChannel.SLACK:
            return await _send_slack(config, event_type, payload, http_client)
        elif channel.channel_type == NotificationChannel.DISCORD:
            return await _send_discord(config, event_type, payload, http_client)
        elif channel.channel_type == NotificationChannel.TELEGRAM:
            return await _send_telegram(config, event_type, payload, http_client)
        elif channel.channel_type == NotificationChannel.WEBHOOK:
            return await _send_webhook(config, event_type, payload, http_client)
        elif channel.channel_type == NotificationChannel.EMAIL:
            return await _send_email(config, event_type, payload)
        else:
            return False, f"Unknown channel type: {channel.channel_type}"

    except Exception as e:
        logger.error(f"Notification send failed ({channel.channel_type}): {e}")
        return False, str(e)[:500]


async def _send_slack(config: dict, event_type: str, payload: dict, http_client: httpx.AsyncClient) -> tuple[bool, str | None]:
    """Send Slack notification via incoming webhook."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return False, "No webhook_url configured"
    safe, reason = _is_safe_url(webhook_url)
    if not safe:
        return False, f"SSRF blocked: {reason}"

    message = _format_message(event_type, payload)
    color = _severity_color(payload.get("severity", "info"))

    slack_payload = {
        "attachments": [{
            "color": color,
            "title": f"🛡️ Recon Sentinel: {_event_title(event_type)}",
            "text": message,
            "fields": [
                {"title": "Target", "value": payload.get("target", "—"), "short": True},
                {"title": "Severity", "value": payload.get("severity", "—").upper(), "short": True},
            ],
            "footer": "Recon Sentinel",
            "ts": int(utc_now().timestamp()),
        }],
    }

    resp = await http_client.post(webhook_url, json=slack_payload)
        if resp.status_code == 200:
            return True, None
        return False, f"Slack returned {resp.status_code}: {resp.text[:200]}"


async def _send_discord(config: dict, event_type: str, payload: dict, http_client: httpx.AsyncClient) -> tuple[bool, str | None]:
    """Send Discord notification via webhook."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return False, "No webhook_url configured"
    safe, reason = _is_safe_url(webhook_url)
    if not safe:
        return False, f"SSRF blocked: {reason}"

    message = _format_message(event_type, payload)
    color = _severity_color_int(payload.get("severity", "info"))

    discord_payload = {
        "embeds": [{
            "title": f"🛡️ {_event_title(event_type)}",
            "description": message,
            "color": color,
            "fields": [
                {"name": "Target", "value": payload.get("target", "—"), "inline": True},
                {"name": "Severity", "value": payload.get("severity", "—").upper(), "inline": True},
            ],
            "footer": {"text": "Recon Sentinel"},
        }],
    }

    resp = await http_client.post(webhook_url, json=discord_payload)
        if resp.status_code in (200, 204):
            return True, None
        return False, f"Discord returned {resp.status_code}: {resp.text[:200]}"


async def _send_telegram(config: dict, event_type: str, payload: dict, http_client: httpx.AsyncClient) -> tuple[bool, str | None]:
    """Send Telegram notification via Bot API."""
    bot_token = config.get("bot_token")
    chat_id = config.get("chat_id")
    if not bot_token or not chat_id:
        return False, "Missing bot_token or chat_id"

    message = f"*🛡️ {_event_title(event_type)}*\n\n{_format_message(event_type, payload)}"

    resp = await http_client.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
        )
        if resp.status_code == 200:
            return True, None
        return False, f"Telegram returned {resp.status_code}: {resp.text[:200]}"


async def _send_webhook(config: dict, event_type: str, payload: dict, http_client: httpx.AsyncClient) -> tuple[bool, str | None]:
    """Send generic webhook POST."""
    url = config.get("url")
    if not url:
        return False, "No url configured"
    safe, reason = _is_safe_url(url)
    if not safe:
        return False, f"SSRF blocked: {reason}"

    headers = config.get("headers", {})
    method = config.get("method", "POST").upper()

    webhook_body = {
        "event": event_type,
        "timestamp": utc_now().isoformat(),
        "payload": payload,
    }

    if method == "POST":
        resp = await http_client.post(url, json=webhook_body, headers=headers)
    else:
        resp = await http_client.request(method, url, json=webhook_body, headers=headers)

        if 200 <= resp.status_code < 300:
            return True, None
        return False, f"Webhook returned {resp.status_code}"


async def _send_email(config: dict, event_type: str, payload: dict) -> tuple[bool, str | None]:
    """Send email notification. Placeholder — needs SMTP integration."""
    # TODO: Implement with aiosmtplib
    return False, "Email notifications not yet implemented (use Slack/Discord/webhook)"


# ─── Formatting Helpers ───────────────────────────────────────

def _event_title(event_type: str) -> str:
    titles = {
        "critical_finding": "Critical Finding Discovered",
        "approval_needed": "Approval Gate Ready",
        "agent_error": "Agent Error",
        "scan_complete": "Scan Completed",
        "new_subdomain": "New Subdomain Found",
        "credential_leak": "Credential Leak Detected",
        "subdomain_takeover": "Subdomain Takeover Found",
        "daily_report": "Daily Summary",
    }
    return titles.get(event_type, event_type.replace("_", " ").title())


def _format_message(event_type: str, payload: dict) -> str:
    value = payload.get("value", "")
    detail = payload.get("detail", "")
    target = payload.get("target", "")
    severity = payload.get("severity", "")

    if event_type == "critical_finding":
        return f"**[{severity.upper()}]** {value}\n{detail[:300]}"
    elif event_type == "credential_leak":
        return f"Credential leak detected: {value}\n{detail[:300]}"
    elif event_type == "subdomain_takeover":
        return f"**Subdomain takeover confirmed!**\n{value}\n{detail[:300]}"
    elif event_type == "approval_needed":
        gate = payload.get("gate_number", "?")
        return f"Approval Gate #{gate} is waiting for your decision.\n{payload.get('ai_summary', '')[:300]}"
    elif event_type == "scan_complete":
        findings = payload.get("total_findings", 0)
        critical = payload.get("critical_count", 0)
        return f"Scan of {target} completed: {findings} findings ({critical} critical)"
    elif event_type == "agent_error":
        agent = payload.get("agent_name", "unknown")
        return f"Agent '{agent}' encountered an error: {detail[:300]}"
    else:
        return f"{value}\n{detail[:300]}" if value else detail[:300]


def _severity_color(severity: str) -> str:
    return {"critical": "#FF0000", "high": "#FF8C00", "medium": "#3B82F6", "low": "#22C55E"}.get(severity, "#64748B")


def _severity_color_int(severity: str) -> int:
    return {"critical": 0xFF0000, "high": 0xFF8C00, "medium": 0x3B82F6, "low": 0x22C55E}.get(severity, 0x64748B)


# ─── Convenience: Fire from Agent Base ────────────────────────

async def notify_critical_finding(scan_id: str, project_id: str, finding: dict) -> None:
    """Called from agent base when a critical/high finding is created."""
    severity = finding.get("severity", "")
    if isinstance(severity, FindingSeverity):
        severity = severity.value

    if severity not in ("critical", "high"):
        return

    event_type = "critical_finding"
    # Special events for specific finding types
    tags = finding.get("tags", [])
    if "subdomain_takeover" in tags or "confirmed" in tags:
        event_type = "subdomain_takeover"
    elif str(finding.get("finding_type", "")) == "credential" or "has_passwords" in tags:
        event_type = "credential_leak"

    dispatch_notification.delay(
        event_type=event_type,
        project_id=project_id,
        scan_id=scan_id,
        payload={
            "value": finding.get("value", ""),
            "detail": finding.get("detail", ""),
            "severity": severity,
            "target": finding.get("value", "")[:50],
            "finding_type": str(finding.get("finding_type", "")),
            "mitre_techniques": finding.get("mitre_technique_ids", []),
        },
    )


async def notify_gate_ready(scan_id: str, project_id: str, gate_number: int, ai_summary: str) -> None:
    """Called when an approval gate is ready for decision."""
    dispatch_notification.delay(
        event_type="approval_needed",
        project_id=project_id,
        scan_id=scan_id,
        payload={"gate_number": gate_number, "ai_summary": ai_summary},
    )


async def notify_scan_complete(scan_id: str, project_id: str, total_findings: int, critical_count: int, target: str) -> None:
    """Called when a scan finishes all phases."""
    dispatch_notification.delay(
        event_type="scan_complete",
        project_id=project_id,
        scan_id=scan_id,
        payload={"total_findings": total_findings, "critical_count": critical_count, "target": target},
    )
