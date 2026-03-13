"""
Recon Sentinel — Timezone Utilities
Single source of truth for UTC timestamps.
Replaces deprecated datetime.utcnow() (removed in Python 3.14+).
"""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)
