"""
Test Suite: Cross-Tenant Isolation
Verifies User B CANNOT access User A's resources across all data paths.

This is the P0 testing gap identified in TECHNICAL-DEBT.md.
Tests the 13 authorize_* helpers that enforce multi-tenant isolation.
"""

import pytest
from httpx import AsyncClient


async def _setup_user_a_data(client: AsyncClient, auth_headers: dict) -> dict:
    """Create a full resource chain for User A: org → project → target → scan."""
    org = await client.post("/api/v1/organizations", json={"name": "User A Org"}, headers=auth_headers)
    org_id = org.json()["id"]

    proj = await client.post(
        f"/api/v1/projects?org_id={org_id}", json={"name": "User A Project"}, headers=auth_headers
    )
    proj_id = proj.json()["id"]

    target = await client.post(
        f"/api/v1/targets?project_id={proj_id}",
        json={"target_value": "usera.example.com", "input_type": "domain"},
        headers=auth_headers,
    )
    target_id = target.json()["id"]

    scan = await client.post(
        "/api/v1/scans",
        json={"target_id": target_id, "profile": "full"},
        headers=auth_headers,
    )
    scan_id = scan.json()["id"]

    return {
        "org_id": org_id,
        "project_id": proj_id,
        "target_id": target_id,
        "scan_id": scan_id,
    }


# ─── Organization Isolation ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_b_cannot_get_user_a_org(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot GET an organization created by User A."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/organizations/{data['org_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404), f"Expected 403/404, got {res.status_code}"


@pytest.mark.asyncio
async def test_user_b_cannot_delete_user_a_org(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot DELETE User A's organization."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.delete(f"/api/v1/organizations/{data['org_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


# ─── Project Isolation ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_b_cannot_get_user_a_project(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot GET a project in User A's org."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/projects/{data['project_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_create_target_in_user_a_project(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot add a target to User A's project."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.post(
        f"/api/v1/targets?project_id={data['project_id']}",
        json={"target_value": "evil.com", "input_type": "domain"},
        headers=second_user_headers,
    )
    assert res.status_code in (403, 404)


# ─── Target Isolation ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_b_cannot_get_user_a_target(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot GET a target belonging to User A's project."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/targets/{data['target_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_delete_user_a_target(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot DELETE User A's target."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.delete(f"/api/v1/targets/{data['target_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


# ─── Scan Isolation ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_b_cannot_get_user_a_scan(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot GET a scan launched by User A."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/scans/{data['scan_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_stop_user_a_scan(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot stop User A's running scan."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.post(f"/api/v1/scans/{data['scan_id']}/stop", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_list_user_a_findings(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot list findings for User A's scan."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/findings?scan_id={data['scan_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_list_user_a_agents(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot list agent runs for User A's scan."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/agents?scan_id={data['scan_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_list_user_a_health_events(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot list health events for User A's scan."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/agents/health?scan_id={data['scan_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_export_user_a_findings(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot export CSV of User A's findings."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/findings/export/csv?scan_id={data['scan_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


# ─── Scope Isolation ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_b_cannot_list_user_a_scope(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot list scope for User A's project."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/scope/{data['project_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_b_cannot_add_scope_to_user_a_project(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot add scope items to User A's project."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.post(
        f"/api/v1/scope/{data['project_id']}",
        json={"item_type": "domain", "item_value": "*.evil.com", "status": "in_scope"},
        headers=second_user_headers,
    )
    assert res.status_code in (403, 404)


# ─── MITRE Heatmap Isolation ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_b_cannot_get_user_a_mitre_heatmap(client: AsyncClient, auth_headers, second_user_headers):
    """User B cannot get MITRE heatmap for User A's scan."""
    data = await _setup_user_a_data(client, auth_headers)
    res = await client.get(f"/api/v1/mitre/heatmap/{data['scan_id']}", headers=second_user_headers)
    assert res.status_code in (403, 404)


# ─── List Endpoints Don't Leak Cross-Tenant Data ─────────────────────


@pytest.mark.asyncio
async def test_user_b_list_scans_empty(client: AsyncClient, auth_headers, second_user_headers):
    """User B's scan list should NOT include User A's scans."""
    await _setup_user_a_data(client, auth_headers)
    res = await client.get("/api/v1/scans", headers=second_user_headers)
    assert res.status_code == 200
    scans = res.json()
    assert len(scans) == 0, f"User B sees {len(scans)} scans that belong to User A"


@pytest.mark.asyncio
async def test_user_b_list_orgs_empty(client: AsyncClient, auth_headers, second_user_headers):
    """User B's org list should NOT include User A's orgs."""
    await _setup_user_a_data(client, auth_headers)
    res = await client.get("/api/v1/organizations", headers=second_user_headers)
    assert res.status_code == 200
    orgs = res.json()
    assert len(orgs) == 0, f"User B sees {len(orgs)} orgs that belong to User A"


@pytest.mark.asyncio
async def test_user_b_list_projects_empty(client: AsyncClient, auth_headers, second_user_headers):
    """User B's project list should NOT include User A's projects."""
    await _setup_user_a_data(client, auth_headers)
    res = await client.get("/api/v1/projects", headers=second_user_headers)
    assert res.status_code == 200
    projects = res.json()
    assert len(projects) == 0, f"User B sees {len(projects)} projects that belong to User A"
