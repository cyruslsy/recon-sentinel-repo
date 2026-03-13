"""
Test Suite 8: Target Collection & Fan-out
Tests the _clean_target method and target collection logic.
"""

import pytest
from app.tasks.orchestrator import ScanOrchestrator, ReconState


class TestCleanTarget:
    """Test the static _clean_target method."""

    def _clean(self, value: str) -> str | None:
        return ScanOrchestrator._clean_target(value)

    def test_plain_domain(self):
        assert self._clean("example.com") == "example.com"

    def test_subdomain(self):
        assert self._clean("staging.example.com") == "staging.example.com"

    def test_strips_https(self):
        assert self._clean("https://example.com") == "example.com"

    def test_strips_http(self):
        assert self._clean("http://example.com") == "example.com"

    def test_strips_path(self):
        assert self._clean("https://example.com/admin/login") == "example.com"

    def test_strips_query(self):
        assert self._clean("https://example.com?foo=bar") == "example.com"

    def test_strips_port(self):
        assert self._clean("https://example.com:8443") == "example.com"

    def test_strips_port_and_path(self):
        assert self._clean("https://staging.example.com:8443/admin?x=1") == "staging.example.com"

    def test_ip_address(self):
        assert self._clean("http://10.0.0.1") == "10.0.0.1"

    def test_ip_with_port(self):
        assert self._clean("10.0.0.1:8080") == "10.0.0.1"

    def test_lowercases(self):
        assert self._clean("STAGING.Example.COM") == "staging.example.com"

    def test_strips_trailing_dot(self):
        assert self._clean("example.com.") == "example.com"

    def test_empty_string(self):
        assert self._clean("") is None

    def test_single_word(self):
        """Single word without dot is not a valid target."""
        assert self._clean("localhost") is None

    def test_preserves_deep_subdomain(self):
        assert self._clean("a.b.c.d.example.com") == "a.b.c.d.example.com"


class TestReconStateDiscoveredTargets:
    """Test that discovered_targets serializes/deserializes correctly."""

    def test_empty_targets_serialize(self):
        state = ReconState(scan_id="abc", target_value="example.com", project_id="xyz")
        j = state.to_json()
        assert j["discovered_targets"] == []

    def test_targets_roundtrip(self):
        state = ReconState(scan_id="abc", target_value="example.com", project_id="xyz")
        state.discovered_targets = ["api.example.com", "staging.example.com"]
        j = state.to_json()
        restored = ReconState.from_json(j)
        assert restored.discovered_targets == ["api.example.com", "staging.example.com"]
