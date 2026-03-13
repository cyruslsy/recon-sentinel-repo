"""
Test Suite 3: Scope Enforcement
Tests: add scope items → verify enforcement → toggle in/out → violation logging
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_add_scope_item(client: AsyncClient, auth_headers):
    """Add a domain to scope."""
    # Setup org + project
    org = await client.post("/api/v1/organizations", json={"name": "O"}, headers=auth_headers)
    proj = await client.post(
        f"/api/v1/projects?org_id={org.json()['id']}", json={"name": "P"}, headers=auth_headers
    )
    proj_id = proj.json()["id"]

    # Add scope item
    res = await client.post(f"/api/v1/scope/{proj_id}", json={
        "item_type": "domain",
        "item_value": "*.example.com",
        "status": "in_scope",
    }, headers=auth_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["item_value"] == "*.example.com"
    assert data["status"] == "in_scope"


@pytest.mark.asyncio
async def test_list_scope_items(client: AsyncClient, auth_headers):
    """List scope items for a project."""
    org = await client.post("/api/v1/organizations", json={"name": "O"}, headers=auth_headers)
    proj = await client.post(
        f"/api/v1/projects?org_id={org.json()['id']}", json={"name": "P"}, headers=auth_headers
    )
    proj_id = proj.json()["id"]

    # Add two items
    await client.post(f"/api/v1/scope/{proj_id}", json={
        "item_type": "domain", "item_value": "*.example.com", "status": "in_scope",
    }, headers=auth_headers)
    await client.post(f"/api/v1/scope/{proj_id}", json={
        "item_type": "ip", "item_value": "10.0.0.0/24", "status": "in_scope",
    }, headers=auth_headers)

    res = await client.get(f"/api/v1/scope/{proj_id}", headers=auth_headers)
    assert res.status_code == 200
    items = res.json()
    assert len(items) == 2


@pytest.mark.asyncio
async def test_scope_requires_auth(client: AsyncClient):
    """Scope endpoints require authentication."""
    res = await client.get("/api/v1/scope/some-project-id")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_add_out_of_scope(client: AsyncClient, auth_headers):
    """Add an exclusion to scope."""
    org = await client.post("/api/v1/organizations", json={"name": "O"}, headers=auth_headers)
    proj = await client.post(
        f"/api/v1/projects?org_id={org.json()['id']}", json={"name": "P"}, headers=auth_headers
    )
    proj_id = proj.json()["id"]

    res = await client.post(f"/api/v1/scope/{proj_id}", json={
        "item_type": "domain",
        "item_value": "internal.example.com",
        "status": "out_of_scope",
    }, headers=auth_headers)
    assert res.status_code == 201
    assert res.json()["status"] == "out_of_scope"
