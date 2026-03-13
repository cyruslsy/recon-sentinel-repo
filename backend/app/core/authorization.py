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
    Report, ScanDiff,
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
