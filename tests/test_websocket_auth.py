"""
Test Suite: WebSocket Authentication
Verifies WebSocket endpoints reject unauthorized connections.

Tests the _authenticate_ws() function and scan authorization on WS connect.
"""

import uuid

import pytest
from httpx import AsyncClient, ASGITransport
from starlette.testclient import TestClient

from app.main import app
from app.core.auth import create_access_token, create_refresh_token


class TestWebSocketAuth:
    """WebSocket authentication and authorization tests."""

    def test_ws_rejects_no_token(self):
        """Connection without token should be closed with 4001."""
        client = TestClient(app)
        scan_id = str(uuid.uuid4())
        with client.websocket_connect(f"/ws/scan/{scan_id}") as ws:
            # Should be closed immediately by server
            pytest.fail("Expected WebSocket to reject connection without token")

    def test_ws_rejects_invalid_token(self):
        """Connection with garbage token should be closed with 4001."""
        client = TestClient(app)
        scan_id = str(uuid.uuid4())
        with client.websocket_connect(f"/ws/scan/{scan_id}?token=garbage.invalid.token") as ws:
            pytest.fail("Expected WebSocket to reject invalid token")

    def test_ws_rejects_refresh_token(self):
        """Connection with a refresh token (not access) should be rejected."""
        client = TestClient(app)
        scan_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())
        refresh_token, _, _ = create_refresh_token(user_id)
        with client.websocket_connect(f"/ws/scan/{scan_id}?token={refresh_token}") as ws:
            pytest.fail("Expected WebSocket to reject refresh token")

    def test_ws_rejects_nonexistent_user(self):
        """Valid token for a user that doesn't exist in DB should be rejected."""
        client = TestClient(app)
        scan_id = str(uuid.uuid4())
        fake_user_id = str(uuid.uuid4())
        token = create_access_token(fake_user_id, "tester")
        with client.websocket_connect(f"/ws/scan/{scan_id}?token={token}") as ws:
            pytest.fail("Expected WebSocket to reject nonexistent user")

    def test_chat_ws_rejects_no_token(self):
        """Chat WebSocket without token should be closed."""
        client = TestClient(app)
        session_id = str(uuid.uuid4())
        with client.websocket_connect(f"/ws/chat/{session_id}") as ws:
            pytest.fail("Expected chat WebSocket to reject connection without token")

    def test_chat_ws_rejects_invalid_token(self):
        """Chat WebSocket with invalid token should be closed."""
        client = TestClient(app)
        session_id = str(uuid.uuid4())
        with client.websocket_connect(f"/ws/chat/{session_id}?token=not.a.real.token") as ws:
            pytest.fail("Expected chat WebSocket to reject invalid token")
