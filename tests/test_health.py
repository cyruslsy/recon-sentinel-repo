"""
Test Suite 6: Health Check & Error Handling
Tests: health endpoint, 404 handling, malformed requests
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Health endpoint returns 200 with status ok."""
    res = await client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_nonexistent_scan_404(client: AsyncClient, auth_headers):
    """Getting a non-existent scan returns 404."""
    res = await client.get(
        "/api/v1/scans/00000000-0000-0000-0000-000000000099",
        headers=auth_headers,
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_invalid_uuid_format(client: AsyncClient, auth_headers):
    """Invalid UUID format returns 422."""
    res = await client.get("/api/v1/scans/not-a-uuid", headers=auth_headers)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_malformed_json_body(client: AsyncClient, auth_headers):
    """Malformed JSON body returns 422."""
    res = await client.post(
        "/api/v1/organizations",
        content="not json",
        headers={**auth_headers, "Content-Type": "application/json"},
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_missing_required_fields(client: AsyncClient, auth_headers):
    """Missing required fields returns 422."""
    res = await client.post("/api/v1/organizations", json={}, headers=auth_headers)
    assert res.status_code == 422
