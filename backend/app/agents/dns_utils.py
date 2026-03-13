"""
Recon Sentinel — Shared DNS Utilities
Reusable async DNS helpers for agents that need CNAME lookups, resolution checks, etc.
"""

from app.agents.base import BaseAgent


async def get_cname(agent: BaseAgent, hostname: str) -> str | None:
    """Resolve CNAME record for a hostname. Returns the CNAME target or None."""
    try:
        result = await agent.run_command(["dig", "+short", hostname, "CNAME"], timeout=5, silent=True)
        if result["returncode"] == 0 and result["stdout"].strip():
            return result["stdout"].strip().split("\n")[0].rstrip(".")
    except Exception:
        pass
    return None


async def resolves(agent: BaseAgent, hostname: str) -> bool:
    """Check if a hostname resolves to any A record."""
    try:
        result = await agent.run_command(["dig", "+short", hostname, "A"], timeout=5, silent=True)
        return bool(result["returncode"] == 0 and result["stdout"].strip())
    except Exception:
        return False


async def is_dangling(agent: BaseAgent, cname: str) -> bool:
    """Check if a CNAME target is dangling (does NOT resolve)."""
    return not await resolves(agent, cname)
