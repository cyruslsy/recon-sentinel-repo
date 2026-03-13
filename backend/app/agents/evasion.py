"""
Recon Sentinel — Evasion Utilities
Provides User-Agent rotation and request timing jitter to avoid
behavioral fingerprinting by WAFs (Cloudflare, Akamai, AWS WAF).

Usage in agents:
    from app.agents.evasion import random_ua, jitter
    cmd.extend(["-H", f"User-Agent: {random_ua()}"])
    await jitter()  # Random 0.1-2s delay between requests
"""

import asyncio
import random

# Real browser User-Agent strings (rotated to avoid fingerprinting)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]


def random_ua() -> str:
    """Return a random real browser User-Agent string."""
    return random.choice(USER_AGENTS)


async def jitter(min_seconds: float = 0.1, max_seconds: float = 2.0) -> None:
    """Random async delay to avoid request timing fingerprinting."""
    await asyncio.sleep(random.uniform(min_seconds, max_seconds))


def random_accept_language() -> str:
    """Return a random Accept-Language header."""
    languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,fr;q=0.8",
        "en;q=0.9",
        "en-US,en;q=0.8,de;q=0.7",
    ]
    return random.choice(languages)


def stealth_headers() -> dict[str, str]:
    """Return a set of headers that look like a real browser."""
    return {
        "User-Agent": random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random_accept_language(),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }
