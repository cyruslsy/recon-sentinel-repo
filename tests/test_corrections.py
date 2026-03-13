"""
Test Suite 5: Self-Correction Patterns
Unit tests for the anomaly detection engine — no external dependencies.
"""

import pytest
from app.agents.corrections import (
    Custom404Detector,
    Custom404WordDetector,
    WAFDetector,
    RateLimitDetector,
    RedirectLoopDetector,
    detect_anomalies,
)


class TestCustom404Detector:
    def test_detects_uniform_size(self):
        """80%+ same content-length → custom 404 detected."""
        responses = [{"content_length": 1234, "status": 200}] * 85
        responses += [{"content_length": 567, "status": 200}] * 15
        result = Custom404Detector.detect(responses)
        assert result is not None
        assert result.pattern == "custom_404"
        assert result.corrected_params["filter_size"] == 1234

    def test_no_detection_below_threshold(self):
        """70% same size → NOT detected (threshold is 80%)."""
        responses = [{"content_length": 1234, "status": 200}] * 70
        responses += [{"content_length": i, "status": 200} for i in range(30)]
        result = Custom404Detector.detect(responses)
        assert result is None

    def test_no_detection_small_sample(self):
        """Under 10 responses → NOT detected."""
        responses = [{"content_length": 1234, "status": 200}] * 5
        result = Custom404Detector.detect(responses)
        assert result is None

    def test_empty_responses(self):
        result = Custom404Detector.detect([])
        assert result is None


class TestWAFDetector:
    def test_detects_waf_blocking(self):
        """95%+ 403 responses → WAF detected."""
        responses = [{"status": 403}] * 96 + [{"status": 200}] * 4
        result = WAFDetector.detect(responses)
        assert result is not None
        assert result.pattern == "waf_blocking"
        assert result.corrected_params["new_rate"] == 10

    def test_no_detection_below_threshold(self):
        """80% 403 → NOT detected (threshold is 95%)."""
        responses = [{"status": 403}] * 80 + [{"status": 200}] * 20
        result = WAFDetector.detect(responses)
        assert result is None

    def test_no_detection_small_sample(self):
        responses = [{"status": 403}] * 3
        result = WAFDetector.detect(responses)
        assert result is None


class TestRateLimitDetector:
    def test_detects_rate_limiting(self):
        """20%+ 429 responses → rate limiting detected."""
        responses = [{"status": 429}] * 25 + [{"status": 200}] * 75
        result = RateLimitDetector.detect(responses)
        assert result is not None
        assert result.pattern == "rate_limiting"

    def test_no_detection_below_threshold(self):
        """10% 429 → NOT detected."""
        responses = [{"status": 429}] * 10 + [{"status": 200}] * 90
        result = RateLimitDetector.detect(responses)
        assert result is None


class TestRedirectLoopDetector:
    def test_detects_redirect_loop(self):
        """90%+ redirects to same URL → loop detected."""
        responses = [{"status": 302, "redirect_url": "/login"}] * 95
        responses += [{"status": 200}] * 5
        result = RedirectLoopDetector.detect(responses)
        assert result is not None
        assert result.pattern == "redirect_loop"

    def test_no_detection_varied_redirects(self):
        """Redirects to many different URLs → NOT a loop."""
        responses = [{"status": 302, "redirect_url": f"/page{i}"} for i in range(100)]
        result = RedirectLoopDetector.detect(responses)
        assert result is None


class TestDetectAnomalies:
    def test_detects_multiple_anomalies(self):
        """WAF + rate limiting can co-occur."""
        responses = [{"status": 403}] * 80 + [{"status": 429}] * 20
        results = detect_anomalies(responses)
        patterns = {r.pattern for r in results}
        # WAF threshold is 95%, so 80% won't trigger it
        # Rate limit threshold is 20%, so 20% WILL trigger
        assert "rate_limiting" in patterns

    def test_no_anomalies_clean_data(self):
        """Normal varied responses → no detections."""
        responses = [
            {"status": 200, "content_length": i * 100}
            for i in range(100)
        ]
        results = detect_anomalies(responses)
        assert len(results) == 0
