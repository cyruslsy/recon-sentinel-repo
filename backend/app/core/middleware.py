"""
Recon Sentinel — Audit Log Middleware
Amendment #21: Logs ALL request statuses, not just successes.
Captures brute-force attempts, scope probes, and rate limit events.
"""

import re
import uuid
from datetime import datetime

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.database import AsyncSessionLocal
from app.models.models import AuditLog


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Intercepts requests and logs audit events to the database.
    
    Logged:
      - All POST, PUT, PATCH, DELETE (regardless of status)
      - All 401, 403, 429 responses (security events)
      - GET on sensitive paths (credentials, audit_log)
    
    Not logged:
      - Successful GET on non-sensitive paths (too noisy)
      - Health checks
      - Static files
    """

    AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    SENSITIVE_READ_PATHS = {"/api/v1/credentials", "/api/v1/audit"}
    SECURITY_STATUS_CODES = {401, 403, 429}
    SKIP_PATHS = {"/api/health", "/api/docs", "/api/redoc", "/api/openapi.json", "/ws/"}

    # Extract UUID from path: /api/v1/scans/abc-123/... → abc-123
    UUID_PATTERN = re.compile(
        r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    )

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip non-auditable paths
        path = request.url.path
        if any(path.startswith(skip) for skip in self.SKIP_PATHS):
            return await call_next(request)

        response = await call_next(request)

        should_audit = (
            request.method in self.AUDIT_METHODS
            or response.status_code in self.SECURITY_STATUS_CODES
            or any(path.startswith(p) for p in self.SENSITIVE_READ_PATHS)
        )

        if should_audit:
            # Fire-and-forget: don't block the response on audit logging
            try:
                await self._log_event(request, response)
            except Exception:
                # Audit logging must never crash the request
                pass

        return response

    async def _log_event(self, request: Request, response: Response) -> None:
        """Write an audit log entry to the database."""
        path = request.url.path

        # Extract user_id from request state (set by auth dependency)
        user_id = getattr(request.state, "user_id", None)

        # Extract resource type from path: /api/v1/{resource}/...
        resource_type = self._extract_resource_type(path)

        # Extract resource ID (UUID) from path
        resource_id = self._extract_resource_id(path)

        async with AsyncSessionLocal() as db:
            entry = AuditLog(
                user_id=uuid.UUID(user_id) if user_id else None,
                action=f"{request.method} {path}",
                resource_type=resource_type,
                resource_id=uuid.UUID(resource_id) if resource_id else None,
                metadata_={
                    "status": response.status_code,
                    "query": str(request.query_params) if request.query_params else None,
                },
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            db.add(entry)
            await db.commit()

    @staticmethod
    def _extract_resource_type(path: str) -> str:
        """Extract resource type from API path."""
        parts = path.strip("/").split("/")
        # /api/v1/{resource}/... → resource
        if len(parts) >= 3 and parts[0] == "api" and parts[1] == "v1":
            return parts[2]
        return "unknown"

    def _extract_resource_id(self, path: str) -> str | None:
        """Extract first UUID from the path."""
        match = self.UUID_PATTERN.search(path)
        return match.group(1) if match else None
