"""
Recon Sentinel — Pydantic Schemas for FastAPI
Request/Response models for all API endpoints.

Naming convention:
  - *Create: POST request body
  - *Update: PATCH request body
  - *Response: GET response body
  - *Brief: Lightweight version for list endpoints
"""

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import (
    AgentStatus, ApprovalDecision, FindingSeverity, FindingType, HealthEventType,
    InputType, NotificationChannel, NotificationEvent, ReportFormat,
    ReportTemplate, ScanPhase, ScanProfile, ScanStatus, ScopeItemType,
    ScopeStatus, UserRole,
)


# ─── Base Config ─────────────────────────────────────────────────────

class SentinelBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ═══════════════════════════════════════════════════════════════════════
# USERS
# ═══════════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    display_name: str = Field(max_length=100)
    role: UserRole = UserRole.TESTER

class UserResponse(SentinelBase):
    id: uuid.UUID
    email: str
    display_name: str
    role: UserRole
    is_active: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime

class UserBrief(SentinelBase):
    id: uuid.UUID
    display_name: str
    role: UserRole


# ═══════════════════════════════════════════════════════════════════════
# ORGANIZATIONS & PROJECTS
# ═══════════════════════════════════════════════════════════════════════

class OrganizationCreate(BaseModel):
    name: str = Field(max_length=255)
    description: Optional[str] = None

class OrganizationResponse(SentinelBase):
    id: uuid.UUID
    name: str
    description: Optional[str]
    created_at: datetime

class ProjectCreate(BaseModel):
    name: str = Field(max_length=255)
    description: Optional[str] = None
    is_bounty_mode: bool = False

class ProjectResponse(SentinelBase):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    description: Optional[str]
    is_bounty_mode: bool
    created_at: datetime


# ═══════════════════════════════════════════════════════════════════════
# TARGETS
# ═══════════════════════════════════════════════════════════════════════

class TargetCreate(BaseModel):
    target_value: str = Field(max_length=500)
    input_type: InputType
    description: Optional[str] = None

class TargetResponse(SentinelBase):
    id: uuid.UUID
    project_id: uuid.UUID
    target_value: str
    input_type: InputType
    description: Optional[str]
    whois_data: Optional[dict] = None
    resolved_ips: Optional[list[str]] = None
    asn_info: Optional[str] = None
    cdn_detected: Optional[str] = None
    registrar: Optional[str] = None
    domain_created: Optional[date] = None
    domain_expires: Optional[date] = None
    nameservers: Optional[list[str]] = None
    tech_stack: Optional[list[str]] = None
    created_at: datetime

class TargetContextResponse(SentinelBase):
    """P1: Target Context Panel data."""
    resolved_ips: list[str] = []
    asn_info: Optional[str] = None
    cdn_detected: Optional[str] = None
    registrar: Optional[str] = None
    domain_created: Optional[date] = None
    domain_expires: Optional[date] = None
    nameservers: list[str] = []
    tech_stack: list[str] = []
    previous_scan_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# SCOPE
# ═══════════════════════════════════════════════════════════════════════

class ScopeItemCreate(BaseModel):
    item_type: ScopeItemType
    item_value: str = Field(max_length=500)
    status: ScopeStatus = ScopeStatus.IN_SCOPE
    note: Optional[str] = None

class ScopeItemResponse(SentinelBase):
    id: uuid.UUID
    item_type: ScopeItemType
    item_value: str
    status: ScopeStatus
    note: Optional[str]
    auto_detected: bool
    created_at: datetime

class ScopeItemUpdate(BaseModel):
    status: ScopeStatus

class ScopeViolationResponse(SentinelBase):
    id: uuid.UUID
    agent_type: str
    attempted_target: str
    reason: str
    blocked_at: datetime

class ScopeCheckRequest(BaseModel):
    target_value: str

class ScopeCheckResponse(BaseModel):
    target_value: str
    is_in_scope: bool
    matched_rule: Optional[ScopeItemResponse] = None


# ═══════════════════════════════════════════════════════════════════════
# SCANS
# ═══════════════════════════════════════════════════════════════════════

class ScanCreate(BaseModel):
    target_id: uuid.UUID
    profile: ScanProfile = ScanProfile.FULL
    engine_id: Optional[uuid.UUID] = None
    rate_limit: Optional[int] = None
    stealth_level: Optional[int] = Field(None, ge=1, le=5)
    custom_wordlist: Optional[str] = None
    path_exclusions: Optional[list[str]] = None

class ScanResponse(SentinelBase):
    id: uuid.UUID
    target_id: uuid.UUID
    target_value: Optional[str] = None  # Denormalized from Target.target_value
    profile: ScanProfile
    status: ScanStatus
    phase: ScanPhase
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    subdomain_count: int
    open_port_count: int
    credential_count: int
    is_archived: bool
    created_at: datetime

class ScanBrief(SentinelBase):
    """Lightweight scan for list views."""
    id: uuid.UUID
    target_value: Optional[str] = None
    profile: ScanProfile
    status: ScanStatus
    phase: ScanPhase
    total_findings: int
    critical_count: int
    high_count: int = 0
    started_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None


# ═══════════════════════════════════════════════════════════════════════
# APPROVAL GATES
# ═══════════════════════════════════════════════════════════════════════

class ApprovalGateResponse(SentinelBase):
    id: uuid.UUID
    scan_id: uuid.UUID
    gate_number: int
    ai_summary: str
    ai_recommendation: dict
    decision: ApprovalDecision
    decided_at: Optional[datetime] = None
    created_at: datetime

class ApprovalGateDecision(BaseModel):
    decision: ApprovalDecision
    user_modifications: Optional[dict] = None


# ═══════════════════════════════════════════════════════════════════════
# AGENT RUNS
# ═══════════════════════════════════════════════════════════════════════

class AgentRunResponse(SentinelBase):
    id: uuid.UUID
    scan_id: uuid.UUID
    agent_type: str
    agent_name: str
    status: AgentStatus
    phase: ScanPhase
    progress_pct: int
    current_tool: Optional[str] = None
    eta_seconds: Optional[int] = None
    tools_used: list[str] = []
    mitre_tags: list[str] = []
    findings_count: int
    retry_count: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    last_log_line: Optional[str] = None
    target_host: Optional[str] = None  # Which subdomain this fan-out agent targets

class AgentRunBrief(SentinelBase):
    id: uuid.UUID
    agent_type: str
    agent_name: str
    status: AgentStatus
    progress_pct: int
    findings_count: int


# ═══════════════════════════════════════════════════════════════════════
# HEALTH EVENTS
# ═══════════════════════════════════════════════════════════════════════

class HealthEventResponse(SentinelBase):
    id: uuid.UUID
    agent_run_id: uuid.UUID
    scan_id: uuid.UUID
    agent_type: Optional[str] = None  # Joined from AgentRun
    agent_name: Optional[str] = None  # Joined from AgentRun
    event_type: HealthEventType
    title: str
    detail: str
    raw_command: Optional[str] = None
    correction_results: Optional[dict] = None
    user_options: Optional[list[str]] = None
    user_decision: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime

class HealthEventDecision(BaseModel):
    """User response to an escalate_user event."""
    decision: str  # one of the user_options


# ═══════════════════════════════════════════════════════════════════════
# FINDINGS
# ═══════════════════════════════════════════════════════════════════════

class FindingResponse(SentinelBase):
    id: uuid.UUID
    scan_id: uuid.UUID
    agent_run_id: uuid.UUID
    finding_type: FindingType
    severity: FindingSeverity
    confidence: Optional[int] = None
    value: str
    detail: str
    mitre_technique_ids: list[str] = []
    mitre_tactic_ids: list[str] = []
    is_false_positive: bool
    user_notes: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None
    tags: list[str] = []
    fingerprint: Optional[str] = None
    verification_status: Optional[str] = "unverified"
    severity_override: Optional[str] = None
    severity_override_reason: Optional[str] = None
    created_at: datetime

class FindingBrief(SentinelBase):
    id: uuid.UUID
    finding_type: FindingType
    severity: FindingSeverity
    value: str
    detail: str
    mitre_technique_ids: list[str] = []

class FindingUpdate(BaseModel):
    is_false_positive: Optional[bool] = None
    user_notes: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None
    tags: Optional[list[str]] = None
    verification_status: Optional[Literal["unverified", "confirmed", "false_positive", "disputed", "remediated"]] = None
    severity_override: Optional[Literal["critical", "high", "medium", "low", "info"]] = None
    severity_override_reason: Optional[str] = None

class FindingBulkAction(BaseModel):
    finding_ids: list[uuid.UUID]
    action: str  # "mark_false_positive", "add_tag", "assign_to", "remove_tag"
    value: Optional[Any] = None  # tag name, user_id, etc.


# ═══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK
# ═══════════════════════════════════════════════════════════════════════

class MitreTechniqueResponse(SentinelBase):
    technique_id: str = Field(alias="id")
    technique_name: str
    tactic_ids: list[str] = []
    tactic_names: list[str] = []
    description: Optional[str] = None
    url: Optional[str] = None
    is_subtechnique: bool

class MitreHeatmapItem(SentinelBase):
    technique_id: str
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    max_severity: Optional[FindingSeverity] = None

class MitreHeatmapResponse(BaseModel):
    scan_id: uuid.UUID
    techniques: list[MitreHeatmapItem]


# ═══════════════════════════════════════════════════════════════════════
# CREDENTIAL LEAKS
# ═══════════════════════════════════════════════════════════════════════

class CredentialLeakResponse(SentinelBase):
    id: uuid.UUID
    email: str
    username: Optional[str] = None
    breach_count: int
    breach_names: Optional[list[str]] = None
    has_password: bool
    has_plaintext: bool
    password_reuse_detected: bool
    sources: list[str] = []
    last_breach_date: Optional[date] = None
    is_redacted: bool

class CredentialLeakSummary(BaseModel):
    total_emails: int
    with_passwords: int
    with_plaintext: int
    password_reuse_count: int


# ═══════════════════════════════════════════════════════════════════════
# SCAN DIFF
# ═══════════════════════════════════════════════════════════════════════

class ScanDiffResponse(SentinelBase):
    id: uuid.UUID
    scan_id: uuid.UUID
    prev_scan_id: uuid.UUID
    new_findings_count: int
    removed_findings_count: int
    new_subdomains: int
    removed_subdomains: int
    new_ports: int
    closed_ports: int
    new_vulns: int
    resolved_vulns: int
    new_credentials: int
    ai_diff_summary: Optional[str] = None

class ScanDiffItemResponse(SentinelBase):
    id: uuid.UUID
    change_type: str
    finding_type: str
    value: str
    detail: Optional[str] = None
    severity: Optional[FindingSeverity] = None


# ═══════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════

class ReportCreate(BaseModel):
    scan_id: uuid.UUID
    template: ReportTemplate
    format: ReportFormat
    company_name: Optional[str] = None
    report_title: Optional[str] = None
    primary_color: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")
    included_sections: list[str] = [
        "executive_summary", "scope", "methodology", "mitre_heatmap",
        "critical_findings", "all_findings", "remediation"
    ]

class ReportResponse(SentinelBase):
    id: uuid.UUID
    scan_id: uuid.UUID
    template: ReportTemplate
    format: ReportFormat
    company_name: Optional[str] = None
    report_title: Optional[str] = None
    file_path: str
    file_size_bytes: Optional[int] = None
    generated_at: datetime


# ═══════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════

class NotificationChannelCreate(BaseModel):
    channel_type: NotificationChannel
    config: dict  # channel-specific: {webhook_url, bot_token, email, ...}
    subscribed_events: list[NotificationEvent] = []

class NotificationChannelResponse(SentinelBase):
    id: uuid.UUID
    channel_type: NotificationChannel
    is_enabled: bool
    subscribed_events: list[str] = []
    created_at: datetime

class NotificationChannelUpdate(BaseModel):
    is_enabled: Optional[bool] = None
    config: Optional[dict] = None
    subscribed_events: Optional[list[NotificationEvent]] = None


# ═══════════════════════════════════════════════════════════════════════
# AI COPILOT CHAT
# ═══════════════════════════════════════════════════════════════════════

class ChatMessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=10000)
    slash_command: Optional[str] = None

class ChatMessageResponse(SentinelBase):
    id: uuid.UUID
    role: str
    content: str
    slash_command: Optional[str] = None
    model_used: Optional[str] = None
    cost_usd: Optional[Decimal] = None
    latency_ms: Optional[int] = None
    created_at: datetime

class ChatSessionResponse(SentinelBase):
    id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    title: Optional[str] = None
    is_active: bool
    created_at: datetime
    message_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════════════════

class ApiKeyCreate(BaseModel):
    service_name: str
    api_key: str  # will be encrypted before storage

class ApiKeyResponse(SentinelBase):
    id: uuid.UUID
    service_name: str
    status: str
    last_used_at: Optional[datetime] = None
    credits_remaining: Optional[int] = None
    # Note: api_key is NEVER returned

class ScanEngineCreate(BaseModel):
    name: str = Field(max_length=255)
    description: Optional[str] = None
    profile: ScanProfile = ScanProfile.CUSTOM
    config_yaml: str

class ScanEngineResponse(SentinelBase):
    id: uuid.UUID
    name: str
    description: Optional[str]
    profile: ScanProfile
    config_yaml: str
    agent_count: int
    is_default: bool


# ═══════════════════════════════════════════════════════════════════════
# WEBSOCKET EVENTS (for real-time UI updates)
# ═══════════════════════════════════════════════════════════════════════

class WSEvent(BaseModel):
    """Base WebSocket event pushed to frontend."""
    event_type: str
    scan_id: uuid.UUID
    data: dict

class WSAgentUpdate(BaseModel):
    agent_run_id: uuid.UUID
    status: AgentStatus
    progress_pct: int
    current_tool: Optional[str] = None
    eta_seconds: Optional[int] = None
    last_log_line: Optional[str] = None
    findings_count: int

class WSFindingNew(BaseModel):
    finding: FindingBrief

class WSHealthEvent(BaseModel):
    event: HealthEventResponse

class WSApprovalNeeded(BaseModel):
    gate: ApprovalGateResponse

class WSScanPhaseChange(BaseModel):
    scan_id: uuid.UUID
    old_phase: ScanPhase
    new_phase: ScanPhase
