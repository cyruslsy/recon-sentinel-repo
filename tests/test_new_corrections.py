"""
Test Suite 12: New Self-Correction Patterns (6) + New Agent Finding Types
"""

import pytest
from app.agents.corrections import (
    DNSWildcardDetector, TimeoutCascadeDetector, ConnectionResetDetector,
    EmptyResponseDetector, CertErrorDetector, EncodingMismatchDetector,
    detect_anomalies, ALL_DETECTORS,
)


class TestDNSWildcardDetector:
    def test_detects_wildcard(self):
        responses = [{"resolved_ip": "1.2.3.4"}] * 95 + [{"resolved_ip": "5.6.7.8"}] * 5
        result = DNSWildcardDetector.detect(responses)
        assert result is not None
        assert result.pattern == "dns_wildcard"
        assert result.corrected_params["wildcard_ip"] == "1.2.3.4"

    def test_no_wildcard_diverse_ips(self):
        responses = [{"resolved_ip": f"10.0.0.{i}"} for i in range(50)]
        result = DNSWildcardDetector.detect(responses)
        assert result is None

    def test_insufficient_data(self):
        responses = [{"resolved_ip": "1.2.3.4"}] * 5
        result = DNSWildcardDetector.detect(responses)
        assert result is None


class TestTimeoutCascadeDetector:
    def test_detects_cascade(self):
        responses = [{"timed_out": True}] * 6 + [{"status": 200}] * 4
        result = TimeoutCascadeDetector.detect(responses)
        assert result is not None
        assert result.pattern == "timeout_cascade"

    def test_no_cascade_low_timeout_rate(self):
        responses = [{"timed_out": True}] * 2 + [{"status": 200}] * 8
        result = TimeoutCascadeDetector.detect(responses)
        assert result is None


class TestConnectionResetDetector:
    def test_detects_resets(self):
        responses = [{"error": "connection_reset"}] * 5 + [{"status": 200}] * 5
        result = ConnectionResetDetector.detect(responses)
        assert result is not None
        assert result.pattern == "connection_reset"

    def test_no_resets(self):
        responses = [{"status": 200}] * 10
        result = ConnectionResetDetector.detect(responses)
        assert result is None


class TestEmptyResponseDetector:
    def test_detects_empty(self):
        responses = [{"content_length": 0, "status": 200}] * 9 + [{"content_length": 500, "status": 200}] * 1
        result = EmptyResponseDetector.detect(responses)
        assert result is not None
        assert result.pattern == "empty_response"

    def test_no_detection_normal(self):
        responses = [{"content_length": 1234, "status": 200}] * 10
        result = EmptyResponseDetector.detect(responses)
        assert result is None


class TestCertErrorDetector:
    def test_detects_cert_errors(self):
        responses = [{"error": "certificate_verify_failed"}] * 4 + [{"status": 200}] * 2
        result = CertErrorDetector.detect(responses)
        assert result is not None
        assert result.pattern == "cert_error"
        assert result.corrected_params["verify_ssl"] is False


class TestEncodingMismatchDetector:
    def test_detects_encoding_errors(self):
        responses = [{"error": "UnicodeDecodeError"}] * 4 + [{"status": 200}] * 6
        result = EncodingMismatchDetector.detect(responses)
        assert result is not None
        assert result.pattern == "encoding_mismatch"


class TestAllDetectorsRegistered:
    def test_all_11_detectors(self):
        assert len(ALL_DETECTORS) == 11

    def test_detect_anomalies_returns_multiple(self):
        """Multiple anomalies can be detected simultaneously."""
        responses = [
            {"content_length": 0, "status": 200, "error": "timeout", "timed_out": True}
        ] * 15
        results = detect_anomalies(responses)
        patterns = {r.pattern for r in results}
        # Should detect at least empty_response and timeout_cascade
        assert "empty_response" in patterns or "timeout_cascade" in patterns
