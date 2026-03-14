# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Recon Sentinel, please report it responsibly:

1. **Email:** cyruslsyx@gmail.com
2. **Subject:** `[SECURITY] Brief description`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (optional)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Critical — 7 days. High — 14 days. Medium — 30 days.
- **Disclosure:** Coordinated disclosure after fix is deployed

## Scope

The following are in scope for security reports:

- Authentication and authorization bypasses
- SQL injection, command injection, SSRF
- Cross-site scripting (XSS) in the frontend
- Privilege escalation (cross-tenant data access)
- Scope enforcement bypass (out-of-scope scanning)
- Sensitive data exposure (credentials, API keys)
- Container escape or privilege escalation
- Denial of service via resource exhaustion

## Out of Scope

- Social engineering attacks
- Physical security attacks
- Denial of service via volumetric flooding
- Issues in third-party dependencies (report to upstream)
- Issues requiring physical access to the server

## Security Architecture

Recon Sentinel implements defense-in-depth:

- **Authentication:** JWT (bcrypt, 15min access tokens, HttpOnly refresh cookies)
- **Authorization:** 3-layer — app-level (authorize_scan/project/org), RLS (PostgreSQL row-level security), ownership checks
- **Encryption:** API keys and SMTP passwords encrypted at rest (Fernet)
- **Network:** SSRF protection with DNS rebinding prevention, private IP blocking
- **Containers:** cap_drop ALL, non-root user, read-only filesystem
- **Subprocess:** Process group isolation, SIGTERM/SIGKILL cleanup
- **Scope:** is_in_scope() SQL function checked before every agent scan

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active  |
| 0.9.x   | ⚠️ Security fixes only |
| < 0.9   | ❌ No      |
