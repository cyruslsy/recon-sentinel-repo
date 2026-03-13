"""
Test Suite 2: Scan Lifecycle
Tests: create org → project → target → launch scan → list scans → gate flow
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_organization(client: AsyncClient, auth_headers):
    """Create an organization."""
    res = await client.post("/api/v1/organizations", json={"name": "Test Org"}, headers=auth_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Test Org"
    assert "id" in data
    return data["id"]


@pytest.mark.asyncio
async def test_create_project(client: AsyncClient, auth_headers):
    """Create org → project."""
    org_res = await client.post("/api/v1/organizations", json={"name": "Org"}, headers=auth_headers)
    org_id = org_res.json()["id"]

    res = await client.post(f"/api/v1/projects?org_id={org_id}", json={"name": "Test Project"}, headers=auth_headers)
    assert res.status_code == 201
    assert res.json()["name"] == "Test Project"


@pytest.mark.asyncio
async def test_create_target(client: AsyncClient, auth_headers):
    """Create org → project → target."""
    org = await client.post("/api/v1/organizations", json={"name": "Org"}, headers=auth_headers)
    org_id = org.json()["id"]
    proj = await client.post(f"/api/v1/projects?org_id={org_id}", json={"name": "Proj"}, headers=auth_headers)
    proj_id = proj.json()["id"]

    res = await client.post(f"/api/v1/targets?project_id={proj_id}", json={
        "target_value": "example.com",
        "input_type": "domain",
    }, headers=auth_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["target_value"] == "example.com"
    assert data["input_type"] == "domain"


@pytest.mark.asyncio
async def test_full_scan_launch(client: AsyncClient, auth_headers):
    """Full lifecycle: org → project → target → launch scan → verify running."""
    # Setup
    org = await client.post("/api/v1/organizations", json={"name": "O"}, headers=auth_headers)
    proj = await client.post(
        f"/api/v1/projects?org_id={org.json()['id']}", json={"name": "P"}, headers=auth_headers
    )
    target = await client.post(
        f"/api/v1/targets?project_id={proj.json()['id']}",
        json={"target_value": "scanme.nmap.org", "input_type": "domain"},
        headers=auth_headers,
    )

    # Launch scan
    res = await client.post("/api/v1/scans", json={
        "target_id": target.json()["id"],
        "profile": "full",
    }, headers=auth_headers)
    assert res.status_code == 201
    scan = res.json()
    assert scan["status"] == "running"
    assert "id" in scan

    # List scans — should include the new one
    list_res = await client.get("/api/v1/scans", headers=auth_headers)
    assert list_res.status_code == 200
    scans = list_res.json()
    assert any(s["id"] == scan["id"] for s in scans)

    # Get single scan
    get_res = await client.get(f"/api/v1/scans/{scan['id']}", headers=auth_headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan["id"]


@pytest.mark.asyncio
async def test_scan_requires_auth(client: AsyncClient):
    """Scan launch without auth returns 401."""
    res = await client.post("/api/v1/scans", json={
        "target_id": "00000000-0000-0000-0000-000000000001",
    })
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_list_scans_empty(client: AsyncClient, auth_headers):
    """List scans with no data returns empty list."""
    res = await client.get("/api/v1/scans", headers=auth_headers)
    assert res.status_code == 200
    assert res.json() == []
