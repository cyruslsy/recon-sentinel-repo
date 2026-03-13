"""
Recon Sentinel — Self-Correction Patterns
Reusable anomaly detection + auto-fix logic.

These are mixins that agents use to detect and correct common failures:
  Pattern 1: Custom 404 (Dir/File agent) — uniform response sizes
  Pattern 2: WAF Blocking (any agent) — >95% 403 responses
  Pattern 3: Rate Limiting — 429 spike detection + backoff

Each pattern follows: detect(data) → diagnose() → correct(agent) → verify()
"""

import logging
from collections import Counter
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CorrectionResult:
    """Outcome of a self-correction attempt."""
    pattern: str
    detected: bool
    corrected: bool
    original_params: dict
    corrected_params: dict
    detail: str


class Custom404Detector:
    """
    Pattern 1: Custom 404 Detection
    Many web servers return 200 for non-existent paths with a custom error page.
    Detection: >80% of responses have the same content-length.
    Correction: Re-run with -fs {dominant_size} to filter false positives.
    """

    @staticmethod
    def detect(responses: list[dict], threshold: float = 0.80) -> CorrectionResult | None:
        """
        Analyze a batch of HTTP responses for uniform content-length.
        responses: [{"status": 200, "content_length": 1234, "path": "/admin"}, ...]
        """
        if not responses:
            return None

        # Count content-length frequencies
        size_counts: dict[int, int] = {}
        for r in responses:
            size = r.get("content_length", 0)
            size_counts[size] = size_counts.get(size, 0) + 1

        if not size_counts:
            return None

        # Find dominant size
        dominant_size, dominant_count = max(size_counts.items(), key=lambda x: x[1])
        ratio = dominant_count / len(responses)

        if ratio >= threshold and len(responses) >= 10:
            return CorrectionResult(
                pattern="custom_404",
                detected=True,
                corrected=False,
                original_params={},
                corrected_params={"filter_size": dominant_size},
                detail=f"Custom 404 detected: {dominant_count}/{len(responses)} responses "
                       f"({ratio:.0%}) have content-length={dominant_size}. "
                       f"Recommend: -fs {dominant_size}",
            )

        return None

    @staticmethod
    def get_correction_args(result: CorrectionResult) -> list[str]:
        """Return ffuf/feroxbuster args to filter the dominant size."""
        size = result.corrected_params.get("filter_size", 0)
        return ["-fs", str(size)]


class Custom404WordDetector:
    """
    Variant: Detect custom 404 by uniform word count instead of content-length.
    Useful when responses have dynamic elements (timestamps, session IDs) but
    the same text structure.
    """

    @staticmethod
    def detect(responses: list[dict], threshold: float = 0.80) -> CorrectionResult | None:
        if not responses:
            return None

        word_counts: dict[int, int] = {}
        for r in responses:
            wc = r.get("word_count", 0)
            word_counts[wc] = word_counts.get(wc, 0) + 1

        if not word_counts:
            return None

        dominant_wc, dominant_count = max(word_counts.items(), key=lambda x: x[1])
        ratio = dominant_count / len(responses)

        if ratio >= threshold and len(responses) >= 10:
            return CorrectionResult(
                pattern="custom_404_words",
                detected=True,
                corrected=False,
                original_params={},
                corrected_params={"filter_words": dominant_wc},
                detail=f"Custom 404 (word count): {ratio:.0%} responses have {dominant_wc} words. "
                       f"Recommend: -fw {dominant_wc}",
            )
        return None


class WAFDetector:
    """
    Pattern 2: WAF Blocking Detection
    Detection: >95% of responses are 403 Forbidden.
    Correction: Reduce rate, rotate user-agent, add delay.
    """

    EVASION_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]

    @staticmethod
    def detect(responses: list[dict], threshold: float = 0.95) -> CorrectionResult | None:
        if not responses or len(responses) < 5:
            return None

        forbidden_count = sum(1 for r in responses if r.get("status") == 403)
        ratio = forbidden_count / len(responses)

        if ratio >= threshold:
            return CorrectionResult(
                pattern="waf_blocking",
                detected=True,
                corrected=False,
                original_params={},
                corrected_params={
                    "reduce_rate": True,
                    "new_rate": 10,       # requests per second
                    "add_delay": 2.0,     # seconds between requests
                    "rotate_ua": True,
                },
                detail=f"WAF blocking detected: {forbidden_count}/{len(responses)} "
                       f"({ratio:.0%}) returned 403. "
                       f"Correction: reduce rate to 10 req/s, rotate user-agent, add 2s delay.",
            )
        return None


class RateLimitDetector:
    """
    Pattern 3: Rate Limiting Detection
    Detection: Spike in 429 responses.
    Correction: Exponential backoff + reduce thread count.
    """

    @staticmethod
    def detect(responses: list[dict], threshold: float = 0.20) -> CorrectionResult | None:
        if not responses or len(responses) < 5:
            return None

        rate_limited = sum(1 for r in responses if r.get("status") == 429)
        ratio = rate_limited / len(responses)

        if ratio >= threshold:
            return CorrectionResult(
                pattern="rate_limiting",
                detected=True,
                corrected=False,
                original_params={},
                corrected_params={
                    "reduce_threads": True,
                    "new_threads": 1,
                    "backoff_seconds": 5.0,
                },
                detail=f"Rate limiting detected: {rate_limited}/{len(responses)} "
                       f"({ratio:.0%}) returned 429. "
                       f"Correction: reduce to 1 thread, add 5s backoff.",
            )
        return None


class RedirectLoopDetector:
    """
    Pattern 4: 302 Redirect Loop Detection
    All responses redirect to the same error/login page.
    """

    @staticmethod
    def detect(responses: list[dict], threshold: float = 0.90) -> CorrectionResult | None:
        if not responses or len(responses) < 5:
            return None

        redirects = [r for r in responses if r.get("status") in (301, 302, 307, 308)]
        if not redirects:
            return None

        ratio = len(redirects) / len(responses)
        if ratio < threshold:
            return None

        # Check if all redirects go to the same location
        locations = [r.get("redirect_url", "") for r in redirects]
        unique_locations = set(locations)

        if len(unique_locations) <= 2:
            return CorrectionResult(
                pattern="redirect_loop",
                detected=True,
                corrected=False,
                original_params={},
                corrected_params={
                    "filter_redirects": True,
                    "redirect_targets": list(unique_locations),
                },
                detail=f"Redirect loop detected: {ratio:.0%} of responses redirect to "
                       f"{unique_locations}. Filtering redirect-to-error responses.",
            )
        return None




# ─── Pattern 6: DNS Wildcard Detection ────────────────────────

class DNSWildcardDetector:
    """
    Detects wildcard DNS records. If >90% of queried subdomains resolve
    to the same IP, it's a wildcard. Filter findings by the wildcard IP.
    """

    @staticmethod
    def detect(responses: list[dict]) -> CorrectionResult | None:
        if len(responses) < 10:
            return None
        resolved_ips = [r.get("resolved_ip") for r in responses if r.get("resolved_ip")]
        if len(resolved_ips) < 10:
            return None
        counter = Counter(resolved_ips)
        most_common_ip, count = counter.most_common(1)[0]
        ratio = count / len(resolved_ips)
        if ratio > 0.90:
            return CorrectionResult(
                detected=True, pattern="dns_wildcard",
                detail=f"{ratio:.0%} of subdomains resolve to {most_common_ip}. Wildcard DNS.",
                corrected_params={"wildcard_ip": most_common_ip, "filter_ip": most_common_ip},
            )
        return None


# ─── Pattern 7: Timeout Cascade ───────────────────────────────

class TimeoutCascadeDetector:
    """Detects >50% timeout rate — target unreachable or aggressive firewall."""

    @staticmethod
    def detect(responses: list[dict]) -> CorrectionResult | None:
        if len(responses) < 5:
            return None
        timeouts = sum(1 for r in responses if r.get("timed_out") or r.get("error") == "timeout")
        ratio = timeouts / len(responses)
        if ratio > 0.50:
            return CorrectionResult(
                detected=True, pattern="timeout_cascade",
                detail=f"{ratio:.0%} requests timed out. Reducing concurrency.",
                corrected_params={"reduce_concurrency": True, "timeout_multiplier": 3},
            )
        return None


# ─── Pattern 8: Connection Reset ──────────────────────────────

class ConnectionResetDetector:
    """Detects TCP RST floods — firewall actively rejecting connections."""

    @staticmethod
    def detect(responses: list[dict]) -> CorrectionResult | None:
        if len(responses) < 5:
            return None
        resets = sum(1 for r in responses if r.get("error") in ("connection_reset", "ConnectionResetError", "ECONNRESET"))
        ratio = resets / len(responses)
        if ratio > 0.40:
            return CorrectionResult(
                detected=True, pattern="connection_reset",
                detail=f"{ratio:.0%} connections reset. Adding inter-request delay.",
                corrected_params={"delay_seconds": 2.0, "max_threads": 1},
            )
        return None


# ─── Pattern 9: Empty Response ────────────────────────────────

class EmptyResponseDetector:
    """Detects empty 200 responses — honeypot, tarpit, or LB misconfiguration."""

    @staticmethod
    def detect(responses: list[dict]) -> CorrectionResult | None:
        if len(responses) < 10:
            return None
        empty = sum(1 for r in responses if r.get("content_length", -1) == 0 and r.get("status", 0) == 200)
        ratio = empty / len(responses)
        if ratio > 0.80:
            return CorrectionResult(
                detected=True, pattern="empty_response",
                detail=f"{ratio:.0%} of 200 responses have empty body. Possible honeypot.",
                corrected_params={"reduce_depth": True, "flag_suspicious": True},
            )
        return None


# ─── Pattern 10: Certificate Validation Error ─────────────────

class CertErrorDetector:
    """Detects SSL cert errors — retry with verification disabled."""

    @staticmethod
    def detect(responses: list[dict]) -> CorrectionResult | None:
        if len(responses) < 3:
            return None
        cert_errors = sum(1 for r in responses if r.get("error") in (
            "ssl_error", "certificate_verify_failed", "CERTIFICATE_VERIFY_FAILED"))
        ratio = cert_errors / len(responses)
        if ratio > 0.50:
            return CorrectionResult(
                detected=True, pattern="cert_error",
                detail=f"{ratio:.0%} cert errors. Retrying with verification disabled.",
                corrected_params={"verify_ssl": False},
            )
        return None


# ─── Pattern 11: Encoding Mismatch ────────────────────────────

class EncodingMismatchDetector:
    """Detects encoding failures — force UTF-8 with error replacement."""

    @staticmethod
    def detect(responses: list[dict]) -> CorrectionResult | None:
        if len(responses) < 5:
            return None
        errors = sum(1 for r in responses if r.get("error") in ("encoding_error", "UnicodeDecodeError"))
        ratio = errors / len(responses)
        if ratio > 0.30:
            return CorrectionResult(
                detected=True, pattern="encoding_mismatch",
                detail=f"{ratio:.0%} encoding errors. Forcing UTF-8.",
                corrected_params={"force_encoding": "utf-8", "errors": "replace"},
            )
        return None


# ─── Convenience: Run All Detectors ───────────────────────────

ALL_DETECTORS = [
    Custom404Detector,
    Custom404WordDetector,
    WAFDetector,
    RateLimitDetector,
    RedirectLoopDetector,
    DNSWildcardDetector,
    TimeoutCascadeDetector,
    ConnectionResetDetector,
    EmptyResponseDetector,
    CertErrorDetector,
    EncodingMismatchDetector,
]


def detect_anomalies(responses: list[dict]) -> list[CorrectionResult]:
    """Run all detectors against a batch of responses. Return detected anomalies."""
    results = []
    for detector_cls in ALL_DETECTORS:
        result = detector_cls.detect(responses)
        if result and result.detected:
            results.append(result)
            logger.info(f"Anomaly detected: {result.pattern} — {result.detail}")
    return results
