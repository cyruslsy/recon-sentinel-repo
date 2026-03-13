"""
Recon Sentinel — Authorization Helpers
Enforces multi-tenancy: users can only access resources within their organizations.

Chain: User → ProjectMember → Project → Org
  - User must be a member of the project's organization
  - Or the user created the resource directly (for org-less quick scans)

Usage in routes:
    scan = await authorize_scan(scan_id, user, db)  # raises 403 if unauthorized
"""

import uuid
from fastapi import HTTPException
from sqlalchemy import select, exists
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    User, Organization, Project, ProjectMember, Target, Scan, Finding,
    Report, ScanDiff, AgentRun, HealthEvent, CredentialLeak,
    NotificationChannelModel, ApprovalGate, ChatSession, ScopeDefinition,
)


async def _user_has_project_access(user: User, project_id: uuid.UUID, db: AsyncSession) -> bool:
    """Check if user is a member of the project's organization or created the project."""
    # Admin bypasses all checks
    if user.role and user.role.value == "admin":
        return True

    # Check if user is a member of any org that owns this project
    result = await db.execute(
        select(exists().where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user.id,
        ))
    )
    if result.scalar():
        return True

    # Fallback: check if user created the project directly
    project = await db.get(Project, project_id)
    if project and project.created_by == user.id:
        return True

    return False


async def authorize_org(org_id: uuid.UUID, user: User, db: AsyncSession) -> Organization:
    """Verify user has access to this organization. Returns org or raises 403."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if user.role and user.role.value == "admin":
        return org

    if org.created_by != user.id:
        # Check membership through any project in this org
        result = await db.execute(
            select(exists().where(
                ProjectMember.user_id == user.id,
                ProjectMember.project_id == Project.id,
                Project.org_id == org_id,
            ))
        )
        if not result.scalar():
            raise HTTPException(status_code=403, detail="Access denied")

    return org


async def authorize_project(project_id: uuid.UUID, user: User, db: AsyncSession) -> Project:
    """Verify user has access to this project. Returns project or raises 403."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if not await _user_has_project_access(user, project_id, db):
        raise HTTPException(status_code=403, detail="Access denied")

    return project


async def authorize_scan(scan_id: uuid.UUID, user: User, db: AsyncSession) -> Scan:
    """Verify user has access to this scan via target→project chain. Returns scan or raises 403."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if user.role and user.role.value == "admin":
        return scan

    # Check: scan.created_by == user
    if scan.created_by == user.id:
        return scan

    # Check: scan.target → project → user has access
    target = await db.get(Target, scan.target_id)
    if target and await _user_has_project_access(user, target.project_id, db):
        return scan

    raise HTTPException(status_code=403, detail="Access denied")


async def authorize_finding(finding_id: uuid.UUID, user: User, db: AsyncSession) -> Finding:
    """Verify user has access to this finding via scan→target→project chain."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Delegate to scan authorization
    await authorize_scan(finding.scan_id, user, db)
    return finding


async def authorize_report(report_id: uuid.UUID, user: User, db: AsyncSession) -> Report:
    """Verify user has access to this report via scan→target→project chain."""
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    await authorize_scan(report.scan_id, user, db)
    return report


async def authorize_credential(cred_id: uuid.UUID, user: User, db: AsyncSession) -> CredentialLeak:
    """Verify user has access to this credential via scan→target→project chain."""
    cred = await db.get(CredentialLeak, cred_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    await authorize_scan(cred.scan_id, user, db)
    return cred


async def authorize_agent_run(agent_run_id: uuid.UUID, user: User, db: AsyncSession) -> AgentRun:
    """Verify user has access to this agent run via scan→target→project chain."""
    agent = await db.get(AgentRun, agent_run_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent run not found")
    await authorize_scan(agent.scan_id, user, db)
    return agent


async def authorize_health_event(event_id: uuid.UUID, user: User, db: AsyncSession) -> HealthEvent:
    """Verify user has access to this health event via scan→target→project chain."""
    event = await db.get(HealthEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Health event not found")
    await authorize_scan(event.scan_id, user, db)
    return event


async def authorize_target(target_id: uuid.UUID, user: User, db: AsyncSession) -> Target:
    """Verify user has access to this target via project→org chain."""
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await authorize_project(target.project_id, user, db)
    return target


async def authorize_notification_channel(channel_id: uuid.UUID, user: User, db: AsyncSession):
    """Verify user has access to this notification channel via project→org chain."""
    channel = await db.get(NotificationChannelModel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    await authorize_project(channel.project_id, user, db)
    return channel


async def authorize_gate(gate_id: uuid.UUID, user: User, db: AsyncSession) -> ApprovalGate:
    """Verify user has access to this approval gate via scan→target→project chain."""
    gate = await db.get(ApprovalGate, gate_id)
    if not gate:
        raise HTTPException(status_code=404, detail="Gate not found")
    await authorize_scan(gate.scan_id, user, db)
    return gate


async def authorize_chat_session(session_id: uuid.UUID, user: User, db: AsyncSession) -> ChatSession:
    """Verify user has access to this chat session."""
    session = await db.get(ChatSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")
    # Chat sessions are user-scoped
    if session.user_id != user.id and not (user.role and user.role.value == "admin"):
        raise HTTPException(status_code=403, detail="Access denied")
    return session


async def authorize_scope_item(item_id: uuid.UUID, user: User, db: AsyncSession) -> ScopeDefinition:
    """Verify user has access to this scope item via project→org chain."""
    item = await db.get(ScopeDefinition, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scope item not found")
    await authorize_project(item.project_id, user, db)
    return item
