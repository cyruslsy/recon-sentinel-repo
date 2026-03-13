"""
Test Suite 10: End-to-End Scan Simulation
Tests the complete scan lifecycle: register → create org → project → target → launch → gate → complete.
Uses mocked Celery tasks to simulate the orchestrator without real scanning tools.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_full_scan_lifecycle(client: AsyncClient):
    """
    Complete E2E flow:
    1. Register user
    2. Create organization
    3. Create project
    4. Add target
    5. Add scope item
    6. Launch scan (mocked Celery)
    7. Verify scan is running
    8. List findings (empty)
    """
    # 1. Register
    reg = await client.post("/api/v1/auth/register", json={
        "email": "e2e@test.com",
        "password": "E2eTestPass123",
        "display_name": "E2E Tester",
    })
    assert reg.status_code == 201
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create org
    org = await client.post("/api/v1/organizations", json={"name": "E2E Org"}, headers=headers)
    assert org.status_code == 201
    org_id = org.json()["id"]

    # 3. Create project
    proj = await client.post(
        f"/api/v1/projects?org_id={org_id}",
        json={"name": "E2E Project"},
        headers=headers,
    )
    assert proj.status_code == 201
    proj_id = proj.json()["id"]

    # 4. Add target
    target = await client.post(
        f"/api/v1/targets?project_id={proj_id}",
        json={"target_value": "scanme.nmap.org", "input_type": "domain"},
        headers=headers,
    )
    assert target.status_code == 201
    target_id = target.json()["id"]

    # 5. Add scope
    scope = await client.post(
        f"/api/v1/scope/{proj_id}",
        json={"item_type": "domain", "item_value": "*.nmap.org", "status": "in_scope"},
        headers=headers,
    )
    assert scope.status_code == 201

    # 6. Launch scan (mock Celery so it doesn't actually dispatch)
    with patch("app.api.scans.start_scan") as mock_celery:
        mock_celery.delay = MagicMock()

        scan = await client.post("/api/v1/scans", json={
            "target_id": target_id,
            "profile": "full",
        }, headers=headers)
        assert scan.status_code == 201
        scan_data = scan.json()
        assert scan_data["status"] == "running"
        scan_id = scan_data["id"]

    # 7. Verify scan exists
    get_scan = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert get_scan.status_code == 200

    # 8. List scans
    scans_list = await client.get("/api/v1/scans", headers=headers)
    assert scans_list.status_code == 200
    assert any(s["id"] == scan_id for s in scans_list.json())

    # 9. List findings (should be empty for new scan)
    findings = await client.get(f"/api/v1/findings?scan_id={scan_id}", headers=headers)
    assert findings.status_code == 200
    assert findings.json() == []

    # 10. Verify scope
    scope_list = await client.get(f"/api/v1/scope/{proj_id}", headers=headers)
    assert scope_list.status_code == 200
    assert len(scope_list.json()) >= 1


@pytest.mark.asyncio
async def test_cross_tenant_isolation(client: AsyncClient, test_user, auth_headers, second_user):
    """Verify user A cannot access user B's scans."""
    # User A creates org + project + target + scan
    org = await client.post("/api/v1/organizations", json={"name": "OrgA"}, headers=auth_headers)
    proj = await client.post(
        f"/api/v1/projects?org_id={org.json()['id']}",
        json={"name": "ProjA"},
        headers=auth_headers,
    )
    target = await client.post(
        f"/api/v1/targets?project_id={proj.json()['id']}",
        json={"target_value": "a.example.com", "input_type": "domain"},
        headers=auth_headers,
    )

    with patch("app.api.scans.start_scan") as mock_celery:
        mock_celery.delay = MagicMock()
        scan = await client.post("/api/v1/scans", json={
            "target_id": target.json()["id"],
            "profile": "quick",
        }, headers=auth_headers)
        scan_id = scan.json()["id"]

    # User B tries to access user A's scan
    from app.core.auth import create_access_token
    token_b = create_access_token(str(second_user.id), second_user.role.value)
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Should get 403 (not 200)
    res = await client.get(f"/api/v1/scans/{scan_id}", headers=headers_b)
    assert res.status_code in (403, 404), f"Expected 403/404 for cross-tenant access, got {res.status_code}"
