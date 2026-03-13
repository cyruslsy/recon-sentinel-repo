"""
Recon Sentinel — Python Enum Definitions
Maps 1:1 to PostgreSQL custom types from schema v1.1
"""

import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    TESTER = "tester"
    AUDITOR = "auditor"


class InputType(str, enum.Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ScanPhase(str, enum.Enum):
    PASSIVE = "passive"
    GATE_1 = "gate_1"
    ACTIVE = "active"
    GATE_2 = "gate_2"
    VULN = "vuln"
    REPORT = "report"
    DONE = "done"


class ScanProfile(str, enum.Enum):
    FULL = "full"
    PASSIVE_ONLY = "passive_only"
    QUICK = "quick"
    STEALTH = "stealth"
    BOUNTY = "bounty"
    CUSTOM = "custom"


class AgentStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SELF_CORRECTING = "self_correcting"
    COMPLETED = "completed"
    ERROR = "error"
    ERROR_RESOLVED = "error_resolved"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, enum.Enum):
    SUBDOMAIN = "subdomain"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    DIRECTORY = "directory"
    SSL_TLS = "ssl_tls"
    EMAIL_SECURITY = "email_security"
    THREAT_INTEL = "threat_intel"
    CLOUD_ASSET = "cloud_asset"
    JS_SECRET = "js_secret"
    API_ENDPOINT = "api_endpoint"
    DNS = "dns"
    SCREENSHOT = "screenshot"
    OSINT = "osint"
    WAF = "waf"
    OTHER = "other"


class ScopeStatus(str, enum.Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"


class ScopeItemType(str, enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    REGEX = "regex"


class HealthEventType(str, enum.Enum):
    ANOMALY_DETECTED = "anomaly_detected"
    SELF_CORRECTION = "self_correction"
    CORRECTION_SUCCESS = "correction_success"
    ESCALATE_USER = "escalate_user"


class ApprovalDecision(str, enum.Enum):
    APPROVED = "approved"
    CUSTOMIZED = "customized"
    SKIPPED = "skipped"
    PENDING = "pending"


class NotificationChannel(str, enum.Enum):
    DISCORD = "discord"
    SLACK = "slack"
    TELEGRAM = "telegram"
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationEvent(str, enum.Enum):
    CRITICAL_FINDING = "critical_finding"
    APPROVAL_NEEDED = "approval_needed"
    AGENT_ERROR = "agent_error"
    SCAN_COMPLETE = "scan_complete"
    NEW_SUBDOMAIN = "new_subdomain"
    CREDENTIAL_LEAK = "credential_leak"
    DAILY_REPORT = "daily_report"


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    DOCX = "docx"
    JSON = "json"
    HTML = "html"


class ReportTemplate(str, enum.Enum):
    FULL = "full"
    EXECUTIVE = "executive"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    COMPLIANCE = "compliance"
