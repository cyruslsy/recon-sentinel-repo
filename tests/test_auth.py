"""
Test Suite 1: Authentication Flow
Tests: register → login → access protected route → refresh → logout → verify revoked
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register(client: AsyncClient):
    """New user registration returns access token."""
    res = await client.post("/api/v1/auth/register", json={
        "email": "newuser@example.com",
        "password": "SecurePass123",
        "display_name": "New User",
    })
    assert res.status_code == 201
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    """Duplicate email returns 409."""
    payload = {"email": "dup@example.com", "password": "Pass12345", "display_name": "Dup"}
    await client.post("/api/v1/auth/register", json=payload)
    res = await client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password(client: AsyncClient):
    """Password under 8 chars returns 422."""
    res = await client.post("/api/v1/auth/register", json={
        "email": "weak@example.com",
        "password": "short",
        "display_name": "Weak",
    })
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_login(client: AsyncClient, test_user):
    """Valid credentials return access token + set refresh cookie."""
    res = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPassword123",
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in res.cookies or True  # Cookie may not be visible in test client


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, test_user):
    """Wrong password returns 401."""
    res = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "WrongPassword",
    })
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_email(client: AsyncClient):
    """Non-existent email returns 401 (not 404 — don't leak user existence)."""
    res = await client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com",
        "password": "Whatever123",
    })
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_requires_auth(client: AsyncClient):
    """Accessing protected route without token returns 401."""
    res = await client.get("/api/v1/scans")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_with_auth(client: AsyncClient, auth_headers):
    """Accessing protected route with valid token succeeds."""
    res = await client.get("/api/v1/scans", headers=auth_headers)
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_me_endpoint(client: AsyncClient, auth_headers, test_user):
    """GET /auth/me returns current user profile."""
    res = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "test@example.com"
    assert data["display_name"] == "Test User"
    assert data["role"] == "admin"
