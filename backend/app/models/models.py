"""
Recon Sentinel — SQLAlchemy ORM Models
Maps 1:1 to PostgreSQL schema v1.1 (29 tables)

All models use:
  - UUID primary keys
  - Async-compatible mapped_column syntax (SQLAlchemy 2.0+)
  - PostgreSQL-specific types (ARRAY, JSONB, INET, ENUM)
  - Proper relationship loading strategies
"""

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import (
    Boolean, CheckConstraint, Date, DateTime, Enum, ForeignKey, Index, Integer,
    Numeric, String, Text, UniqueConstraint, text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin
from app.core.tz import utc_now
from app.models.enums import (
    AgentStatus, ApprovalDecision, FindingSeverity, FindingType, HealthEventType,
    InputType, NotificationChannel, NotificationEvent, ReportFormat,
    ReportTemplate, ScanPhase, ScanProfile, ScanStatus, ScopeItemType,
    ScopeStatus, UserRole,
)

# Type alias for cleaner column definitions
UUID_PK = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: USERS & ACCESS
# ═══════════════════════════════════════════════════════════════════════════

class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = UUID_PK
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", create_type=False), default=UserRole.TESTER
    )
    api_key_hash: Mapped[Optional[str]] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Relationships
    organizations: Mapped[list["Organization"]] = relationship(back_populates="creator", foreign_keys="Organization.created_by")
    project_memberships: Mapped[list["ProjectMember"]] = relationship(back_populates="user")

    __table_args__ = (
        Index("idx_users_api_key", "api_key_hash", postgresql_where=text("api_key_hash IS NOT NULL")),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: ORGANIZATIONS & PROJECTS
# ═══════════════════════════════════════════════════════════════════════════

class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = UUID_PK
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)

    creator: Mapped["User"] = relationship(back_populates="organizations", foreign_keys=[created_by])
    projects: Mapped[list["Project"]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = UUID_PK
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_bounty_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)

    organization: Mapped["Organization"] = relationship(back_populates="projects")
    targets: Mapped[list["Target"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scope_definitions: Mapped[list["ScopeDefinition"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    members: Mapped[list["ProjectMember"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    notification_channels: Mapped[list["NotificationChannelModel"]] = relationship(back_populates="project", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_projects_org", "org_id"),)


class ProjectMember(Base):
    __tablename__ = "project_members"

    id: Mapped[uuid.UUID] = UUID_PK
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role", create_type=False), default=UserRole.TESTER)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    project: Mapped["Project"] = relationship(back_populates="members")
    user: Mapped["User"] = relationship(back_populates="project_memberships")

    __table_args__ = (UniqueConstraint("project_id", "user_id"),)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: TARGETS & SCOPE
# ═══════════════════════════════════════════════════════════════════════════

class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = UUID_PK
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    target_value: Mapped[str] = mapped_column(String(500), nullable=False)
    input_type: Mapped[InputType] = mapped_column(Enum(InputType, name="input_type", create_type=False), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Target context panel data (cached WHOIS/DNS)
    whois_data: Mapped[Optional[dict]] = mapped_column(JSONB)
    resolved_ips: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    asn_info: Mapped[Optional[str]] = mapped_column(String(255))
    cdn_detected: Mapped[Optional[str]] = mapped_column(String(100))
    registrar: Mapped[Optional[str]] = mapped_column(String(255))
    domain_created: Mapped[Optional[date]] = mapped_column(Date)
    domain_expires: Mapped[Optional[date]] = mapped_column(Date)
    nameservers: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    tech_stack: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))

    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)

    project: Mapped["Project"] = relationship(back_populates="targets")
    scans: Mapped[list["Scan"]] = relationship(back_populates="target", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_targets_project", "project_id"),
        Index("idx_targets_value", "target_value"),
    )


class ScopeDefinition(Base):
    __tablename__ = "scope_definitions"

    id: Mapped[uuid.UUID] = UUID_PK
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    item_type: Mapped[ScopeItemType] = mapped_column(Enum(ScopeItemType, name="scope_item_type", create_type=False), nullable=False)
    item_value: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[ScopeStatus] = mapped_column(Enum(ScopeStatus, name="scope_status", create_type=False), default=ScopeStatus.IN_SCOPE)
    note: Mapped[Optional[str]] = mapped_column(Text)
    auto_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    added_by: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"))

    project: Mapped["Project"] = relationship(back_populates="scope_definitions")

    __table_args__ = (
        Index("idx_scope_project", "project_id"),
        Index("idx_scope_status", "project_id", "status"),
    )


class ScopeViolation(Base):
    __tablename__ = "scope_violations"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    agent_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("agent_runs.id", ondelete="SET NULL"))
    agent_type: Mapped[str] = mapped_column(String(100), nullable=False)
    attempted_target: Mapped[str] = mapped_column(String(500), nullable=False)
    matched_rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scope_definitions.id"))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (Index("idx_scope_violations_scan", "scan_id"),)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: SCANS & EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

class ScanEngine(Base, TimestampMixin):
    __tablename__ = "scan_engines"

    id: Mapped[uuid.UUID] = UUID_PK
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    profile: Mapped[ScanProfile] = mapped_column(Enum(ScanProfile, name="scan_profile", create_type=False), default=ScanProfile.CUSTOM)
    config_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    config_json: Mapped[Optional[dict]] = mapped_column(JSONB)  # FIX #11: parsed YAML
    agent_count: Mapped[int] = mapped_column(Integer, default=0)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = UUID_PK
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    engine_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scan_engines.id"))
    profile: Mapped[ScanProfile] = mapped_column(Enum(ScanProfile, name="scan_profile", create_type=False), default=ScanProfile.FULL)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, name="scan_status", create_type=False), default=ScanStatus.PENDING)
    phase: Mapped[ScanPhase] = mapped_column(Enum(ScanPhase, name="scan_phase", create_type=False), default=ScanPhase.PASSIVE)
    langgraph_checkpoint: Mapped[Optional[dict]] = mapped_column(JSONB)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer)

    # Denormalized stats
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    subdomain_count: Mapped[int] = mapped_column(Integer, default=0)
    open_port_count: Mapped[int] = mapped_column(Integer, default=0)
    credential_count: Mapped[int] = mapped_column(Integer, default=0)

    # Config overrides
    rate_limit: Mapped[Optional[int]] = mapped_column(Integer)
    stealth_level: Mapped[Optional[int]] = mapped_column(Integer)
    custom_wordlist: Mapped[Optional[str]] = mapped_column(String(500))
    path_exclusions: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))

    # Data retention (ADD C)
    retain_until: Mapped[Optional[date]] = mapped_column(Date)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)

    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)

    # Relationships
    target: Mapped["Target"] = relationship(back_populates="scans")
    agent_runs: Mapped[list["AgentRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    approval_gates: Mapped[list["ApprovalGate"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    health_events: Mapped[list["HealthEvent"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("stealth_level IS NULL OR (stealth_level >= 1 AND stealth_level <= 5)", name="ck_stealth_level"),
        Index("idx_scans_target", "target_id"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_created", "created_at"),
        Index("idx_scans_not_archived", "target_id", postgresql_where=text("is_archived = false")),
    )


class ApprovalGate(Base):
    __tablename__ = "approval_gates"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    gate_number: Mapped[int] = mapped_column(Integer, nullable=False)
    ai_summary: Mapped[str] = mapped_column(Text, nullable=False)
    ai_recommendation: Mapped[dict] = mapped_column(JSONB, nullable=False)
    decision: Mapped[ApprovalDecision] = mapped_column(
        Enum(ApprovalDecision, name="approval_decision", create_type=False), default=ApprovalDecision.PENDING
    )
    user_modifications: Mapped[Optional[dict]] = mapped_column(JSONB)
    decided_by: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"))
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    llm_model_used: Mapped[Optional[str]] = mapped_column(String(100))
    llm_tokens_in: Mapped[Optional[int]] = mapped_column(Integer)
    llm_tokens_out: Mapped[Optional[int]] = mapped_column(Integer)
    llm_cost_usd: Mapped[Optional[Decimal]] = mapped_column(Numeric(10, 6))

    scan: Mapped["Scan"] = relationship(back_populates="approval_gates")

    __table_args__ = (
        CheckConstraint("gate_number IN (1, 2)", name="ck_gate_number"),
        UniqueConstraint("scan_id", "gate_number", name="uq_approval_gate_per_scan"),  # FIX #5
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: AGENT EXECUTION & HEALTH
# ═══════════════════════════════════════════════════════════════════════════

class AgentRun(Base, TimestampMixin):
    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    agent_type: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, name="agent_status", create_type=False), default=AgentStatus.PENDING
    )
    phase: Mapped[ScanPhase] = mapped_column(Enum(ScanPhase, name="scan_phase", create_type=False), nullable=False)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0)
    current_tool: Mapped[Optional[str]] = mapped_column(String(255))
    eta_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    tools_used: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    mitre_tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    config_override: Mapped[Optional[dict]] = mapped_column(JSONB)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    last_log_line: Mapped[Optional[str]] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="agent_runs")
    health_events: Mapped[list["HealthEvent"]] = relationship(back_populates="agent_run", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="agent_run")

    __table_args__ = (
        CheckConstraint("progress_pct >= 0 AND progress_pct <= 100", name="ck_progress_pct"),
        Index("idx_agent_runs_scan", "scan_id"),
        Index("idx_agent_runs_status", "status"),
        Index("idx_agent_runs_type", "agent_type"),
    )


class HealthEvent(Base):
    __tablename__ = "health_events"

    id: Mapped[uuid.UUID] = UUID_PK
    agent_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[HealthEventType] = mapped_column(
        Enum(HealthEventType, name="health_event_type", create_type=False), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    raw_command: Mapped[Optional[str]] = mapped_column(Text)
    correction_results: Mapped[Optional[dict]] = mapped_column(JSONB)
    user_options: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    user_decision: Mapped[Optional[str]] = mapped_column(Text)
    decided_by: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"))
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    agent_run: Mapped["AgentRun"] = relationship(back_populates="health_events")
    scan: Mapped["Scan"] = relationship(back_populates="health_events")

    __table_args__ = (
        Index("idx_health_events_agent", "agent_run_id"),
        Index("idx_health_events_scan", "scan_id"),
        Index("idx_health_events_type", "event_type"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: FINDINGS & MITRE
# ═══════════════════════════════════════════════════════════════════════════

class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    agent_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False)

    finding_type: Mapped[FindingType] = mapped_column(
        Enum(FindingType, name="finding_type_enum", create_type=False), nullable=False
    )
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", create_type=False), nullable=False
    )
    confidence: Mapped[Optional[int]] = mapped_column(Integer)
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)

    # MITRE ATT&CK (first-class)
    mitre_technique_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    mitre_tactic_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)

    raw_data: Mapped[Optional[dict]] = mapped_column(JSONB)

    # User annotations
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    user_notes: Mapped[Optional[str]] = mapped_column(Text)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")  # FIX #4
    )
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)  # FIX #10

    # Deduplication
    fingerprint: Mapped[Optional[str]] = mapped_column(String(255))
    first_seen_scan: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL")  # FIX #8
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="findings", foreign_keys=[scan_id])
    agent_run: Mapped["AgentRun"] = relationship(back_populates="findings")

    __table_args__ = (
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 100)", name="ck_confidence"),
        Index("idx_findings_scan", "scan_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_type", "finding_type"),
        Index("idx_findings_mitre", "mitre_technique_ids", postgresql_using="gin"),
        Index("idx_findings_fingerprint", "fingerprint"),
        Index("idx_findings_tags", "tags", postgresql_using="gin"),
        Index("idx_findings_false_positive", "scan_id", postgresql_where=text("is_false_positive = false")),
    )


class MitreTechnique(Base):
    """Static reference table — pre-populated with MITRE ATT&CK techniques."""
    __tablename__ = "mitre_techniques"

    # Override: use technique_id as PK instead of UUID
    id: Mapped[str] = mapped_column(String(20), primary_key=True, name="technique_id")
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)     # FIX #3: multi-tactic
    tactic_names: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)   # FIX #3
    description: Mapped[Optional[str]] = mapped_column(Text)
    url: Mapped[Optional[str]] = mapped_column(String(500))
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("idx_mitre_tactics", "tactic_ids", postgresql_using="gin"),
    )


class MitreFindingCount(Base):
    """Trigger-maintained aggregate — replaces materialized view (FIX #12)."""
    __tablename__ = "mitre_finding_counts"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    max_severity: Mapped[Optional[FindingSeverity]] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", create_type=False)
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: SPECIALIZED FINDING TABLES
# ═══════════════════════════════════════════════════════════════════════════

class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[uuid.UUID] = UUID_PK
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    subdomain: Mapped[str] = mapped_column(String(500), nullable=False)
    resolved_ips: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    http_status: Mapped[Optional[int]] = mapped_column(Integer)
    http_title: Mapped[Optional[str]] = mapped_column(String(500))
    content_length: Mapped[Optional[int]] = mapped_column(Integer)
    tech_detected: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    has_login_panel: Mapped[bool] = mapped_column(Boolean, default=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    cdn_detected: Mapped[Optional[str]] = mapped_column(String(100))

    __table_args__ = (
        Index("idx_subdomains_scan", "scan_id"),
        Index("idx_subdomains_domain", "subdomain"),
    )


class OpenPort(Base):
    __tablename__ = "open_ports"

    id: Mapped[uuid.UUID] = UUID_PK
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    host: Mapped[str] = mapped_column(String(500), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[Optional[str]] = mapped_column(String(100))
    service_version: Mapped[Optional[str]] = mapped_column(String(255))
    banner: Mapped[Optional[str]] = mapped_column(Text)
    is_filtered: Mapped[bool] = mapped_column(Boolean, default=False)
    scan_method: Mapped[Optional[str]] = mapped_column(String(50))

    __table_args__ = (
        Index("idx_ports_scan", "scan_id"),
        Index("idx_ports_host_port", "host", "port"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = UUID_PK
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", create_type=False), nullable=False
    )  # FIX #2: denormalized
    host: Mapped[str] = mapped_column(String(500), nullable=False)
    vuln_id: Mapped[Optional[str]] = mapped_column(String(100))
    vuln_name: Mapped[str] = mapped_column(String(500), nullable=False)
    vuln_type: Mapped[Optional[str]] = mapped_column(String(100))
    cvss_score: Mapped[Optional[Decimal]] = mapped_column(Numeric(3, 1))
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20))
    affected_component: Mapped[Optional[str]] = mapped_column(String(500))
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text)
    remediation: Mapped[Optional[str]] = mapped_column(Text)
    nuclei_template: Mapped[Optional[str]] = mapped_column(String(255))
    is_in_kev: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        Index("idx_vulns_scan", "scan_id"),
        Index("idx_vulns_vuln_id", "vuln_id"),
        Index("idx_vulns_severity", "severity"),  # FIX #2: clean index
    )


class CredentialLeak(Base):
    __tablename__ = "credential_leaks"

    id: Mapped[uuid.UUID] = UUID_PK
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String(500), nullable=False)
    username: Mapped[Optional[str]] = mapped_column(String(255))
    breach_count: Mapped[int] = mapped_column(Integer, default=0)
    breach_names: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    has_password: Mapped[bool] = mapped_column(Boolean, default=False)
    has_plaintext: Mapped[bool] = mapped_column(Boolean, default=False)
    password_hash_types: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))

    # FIX #7: Actual credential storage
    hash_value: Mapped[Optional[str]] = mapped_column(Text)
    password_hash_encrypted: Mapped[Optional[str]] = mapped_column(Text)  # encrypted with pgcrypto

    password_reuse_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    reuse_across_breaches: Mapped[int] = mapped_column(Integer, default=0)
    sources: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    last_breach_date: Mapped[Optional[date]] = mapped_column(Date)
    is_redacted: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        Index("idx_creds_scan", "scan_id"),
        Index("idx_creds_email", "email"),
    )


class DirectoryDiscovery(Base):
    __tablename__ = "directory_discoveries"

    id: Mapped[uuid.UUID] = UUID_PK
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    host: Mapped[str] = mapped_column(String(500), nullable=False)
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    http_status: Mapped[int] = mapped_column(Integer, nullable=False)
    content_length: Mapped[Optional[int]] = mapped_column(Integer)
    content_type: Mapped[Optional[str]] = mapped_column(String(255))
    redirect_url: Mapped[Optional[str]] = mapped_column(String(1000))
    is_admin_panel: Mapped[bool] = mapped_column(Boolean, default=False)
    is_backup_file: Mapped[bool] = mapped_column(Boolean, default=False)
    is_config_file: Mapped[bool] = mapped_column(Boolean, default=False)
    is_api_endpoint: Mapped[bool] = mapped_column(Boolean, default=False)
    tool_used: Mapped[Optional[str]] = mapped_column(String(100))
    wordlist_used: Mapped[Optional[str]] = mapped_column(String(255))
    filter_applied: Mapped[Optional[str]] = mapped_column(String(255))

    __table_args__ = (
        Index("idx_dirs_scan", "scan_id"),
        Index("idx_dirs_path", "path"),
    )


class Screenshot(Base):
    __tablename__ = "screenshots"

    id: Mapped[uuid.UUID] = UUID_PK
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    http_status: Mapped[Optional[int]] = mapped_column(Integer)
    page_title: Mapped[Optional[str]] = mapped_column(String(500))
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    thumbnail_path: Mapped[Optional[str]] = mapped_column(String(500))
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    tech_detected: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    rendered_with: Mapped[str] = mapped_column(String(50), default="gowitness")

    __table_args__ = (Index("idx_screenshots_scan", "scan_id"),)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: SCAN DIFF
# ═══════════════════════════════════════════════════════════════════════════

class ScanDiff(Base):
    __tablename__ = "scan_diffs"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    prev_scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    new_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    removed_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    new_subdomains: Mapped[int] = mapped_column(Integer, default=0)
    removed_subdomains: Mapped[int] = mapped_column(Integer, default=0)
    new_ports: Mapped[int] = mapped_column(Integer, default=0)
    closed_ports: Mapped[int] = mapped_column(Integer, default=0)
    new_vulns: Mapped[int] = mapped_column(Integer, default=0)
    resolved_vulns: Mapped[int] = mapped_column(Integer, default=0)
    new_credentials: Mapped[int] = mapped_column(Integer, default=0)
    ai_diff_summary: Mapped[Optional[str]] = mapped_column(Text)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    diff_items: Mapped[list["ScanDiffItem"]] = relationship(back_populates="diff", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("scan_id", "prev_scan_id", name="uq_scan_diff_pair"),  # FIX #6
        Index("idx_scan_diffs_scan", "scan_id"),
    )


class ScanDiffItem(Base):
    __tablename__ = "scan_diff_items"

    id: Mapped[uuid.UUID] = UUID_PK
    diff_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_diffs.id", ondelete="CASCADE"), nullable=False)
    change_type: Mapped[str] = mapped_column(String(20), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    detail: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[FindingSeverity]] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", create_type=False)
    )
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))

    diff: Mapped["ScanDiff"] = relationship(back_populates="diff_items")

    __table_args__ = (
        CheckConstraint("change_type IN ('new', 'removed', 'changed')", name="ck_change_type"),
        Index("idx_diff_items_diff", "diff_id"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9: REPORTS
# ═══════════════════════════════════════════════════════════════════════════

class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    template: Mapped[ReportTemplate] = mapped_column(Enum(ReportTemplate, name="report_template", create_type=False), nullable=False)
    format: Mapped[ReportFormat] = mapped_column(Enum(ReportFormat, name="report_format", create_type=False), nullable=False)
    company_name: Mapped[Optional[str]] = mapped_column(String(255))
    report_title: Mapped[Optional[str]] = mapped_column(String(500))
    primary_color: Mapped[Optional[str]] = mapped_column(String(7))
    logo_path: Mapped[Optional[str]] = mapped_column(String(500))
    included_sections: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    ai_executive_summary: Mapped[Optional[str]] = mapped_column(Text)
    ai_model_used: Mapped[Optional[str]] = mapped_column(String(100))
    ai_tokens_used: Mapped[Optional[int]] = mapped_column(Integer)
    ai_cost_usd: Mapped[Optional[Decimal]] = mapped_column(Numeric(10, 6))
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    generated_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (Index("idx_reports_scan", "scan_id"),)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10: NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════

class NotificationChannelModel(Base, TimestampMixin):
    __tablename__ = "notification_channels"

    id: Mapped[uuid.UUID] = UUID_PK
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    channel_type: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel", create_type=False), nullable=False
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    subscribed_events: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)

    project: Mapped["Project"] = relationship(back_populates="notification_channels")
    logs: Mapped[list["NotificationLog"]] = relationship(back_populates="channel", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_notif_channels_project", "project_id"),)


class NotificationLog(Base):
    __tablename__ = "notification_log"

    id: Mapped[uuid.UUID] = UUID_PK
    channel_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[NotificationEvent] = mapped_column(
        Enum(NotificationEvent, name="notification_event", create_type=False), nullable=False
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    channel: Mapped["NotificationChannelModel"] = relationship(back_populates="logs")

    __table_args__ = (
        Index("idx_notif_log_channel", "channel_id"),
        Index("idx_notif_log_status", "status"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 11: AI COPILOT CHAT
# ═══════════════════════════════════════════════════════════════════════════

class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    title: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    messages: Mapped[list["ChatMessage"]] = relationship(back_populates="session", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[uuid.UUID] = UUID_PK
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    slash_command: Mapped[Optional[str]] = mapped_column(String(100))
    model_used: Mapped[Optional[str]] = mapped_column(String(100))
    tokens_in: Mapped[Optional[int]] = mapped_column(Integer)
    tokens_out: Mapped[Optional[int]] = mapped_column(Integer)
    cost_usd: Mapped[Optional[Decimal]] = mapped_column(Numeric(10, 6))
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer)

    session: Mapped["ChatSession"] = relationship(back_populates="messages")

    __table_args__ = (
        CheckConstraint("role IN ('user', 'ai', 'system')", name="ck_chat_role"),
        Index("idx_chat_messages_session", "session_id"),
        Index("idx_chat_messages_created", "created_at"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 12: API KEYS & LLM TRACKING
# ═══════════════════════════════════════════════════════════════════════════

class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = UUID_PK
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    service_name: Mapped[str] = mapped_column(String(100), nullable=False)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="valid")
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    credits_remaining: Mapped[Optional[int]] = mapped_column(Integer)

    __table_args__ = (Index("idx_api_keys_service", "service_name"),)


class LlmUsageLog(Base):
    __tablename__ = "llm_usage_log"

    id: Mapped[uuid.UUID] = UUID_PK
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    task_type: Mapped[str] = mapped_column(String(100), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tokens_input: Mapped[int] = mapped_column(Integer, nullable=False)
    tokens_output: Mapped[int] = mapped_column(Integer, nullable=False)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 6), nullable=False)
    cached_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer)

    __table_args__ = (
        Index("idx_llm_usage_scan", "scan_id"),
        Index("idx_llm_usage_date", "created_at"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 13: PLUGINS
# ═══════════════════════════════════════════════════════════════════════════

class Plugin(Base, TimestampMixin):
    __tablename__ = "plugins"

    id: Mapped[uuid.UUID] = UUID_PK
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    author: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    repository_url: Mapped[Optional[str]] = mapped_column(String(500))
    agent_type: Mapped[str] = mapped_column(String(100), nullable=False)
    mitre_tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    required_api_keys: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    config_schema: Mapped[Optional[dict]] = mapped_column(JSONB)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_sandboxed: Mapped[bool] = mapped_column(Boolean, default=True)
    installed_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (Index("idx_plugins_agent_type", "agent_type"),)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 14: AUDIT LOG (FIX #9)
# ═══════════════════════════════════════════════════════════════════════════

class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = UUID_PK
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(PgUUID(as_uuid=True))
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB)
    ip_address: Mapped[Optional[str]] = mapped_column(INET)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_action", "action"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
        Index("idx_audit_created", "created_at"),
    )
