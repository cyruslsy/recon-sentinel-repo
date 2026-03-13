"""
Test Suite 4: Findings
Tests: list findings, filter by severity, search, bulk mark false positive
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_findings_requires_auth(client: AsyncClient):
    """Findings endpoint requires authentication."""
    res = await client.get("/api/v1/findings?scan_id=some-id")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_list_findings_empty(client: AsyncClient, auth_headers):
    """List findings with no scan data returns empty list."""
    res = await client.get("/api/v1/findings?scan_id=00000000-0000-0000-0000-000000000001", headers=auth_headers)
    assert res.status_code == 200
    assert res.json() == []


@pytest.mark.asyncio
async def test_findings_stats_requires_auth(client: AsyncClient):
    """Finding stats require authentication."""
    res = await client.get("/api/v1/findings/stats?scan_id=some-id")
    assert res.status_code == 401
