# Recon Sentinel — API Examples

Base URL: `http://localhost/api/v1`

## Authentication

```bash
# Register
curl -X POST http://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "pentester@example.com", "password": "SecurePass123!", "display_name": "Pentester"}'

# Login
TOKEN=$(curl -s -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "pentester@example.com", "password": "SecurePass123!"}' | jq -r '.access_token')

# All subsequent requests use:
AUTH="Authorization: Bearer $TOKEN"
```

## Setup: Org → Project → Target → Scope

```bash
# Create organization
ORG_ID=$(curl -s -X POST http://localhost/api/v1/organizations \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name": "My Pentest Firm"}' | jq -r '.id')

# Create project
PROJ_ID=$(curl -s -X POST "http://localhost/api/v1/projects?org_id=$ORG_ID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name": "Client Engagement Q1"}' | jq -r '.id')

# Add target
TARGET_ID=$(curl -s -X POST "http://localhost/api/v1/targets?project_id=$PROJ_ID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"target_value": "example.com", "input_type": "domain"}' | jq -r '.id')

# Add scope (wildcard domain)
curl -X POST "http://localhost/api/v1/scope/$PROJ_ID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"item_type": "domain", "item_value": "*.example.com", "status": "in_scope"}'
```

## Launch Scan

```bash
# Start full scan
SCAN_ID=$(curl -s -X POST http://localhost/api/v1/scans \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"target_id\": \"$TARGET_ID\", \"profile\": \"full\"}" | jq -r '.id')

# Check scan status
curl -s "http://localhost/api/v1/scans/$SCAN_ID" -H "$AUTH" | jq '.status, .phase'

# Approve gate 1 (after passive phase completes)
curl -X POST "http://localhost/api/v1/scans/$SCAN_ID/gates/1/decide" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"decision": "approved"}'

# Stop a running scan
curl -X POST "http://localhost/api/v1/scans/$SCAN_ID/stop" -H "$AUTH"

# Resume a paused/errored scan from checkpoint
curl -X POST "http://localhost/api/v1/scans/$SCAN_ID/resume" -H "$AUTH"
```

## View Results

```bash
# List findings (paginated)
curl -s "http://localhost/api/v1/findings?scan_id=$SCAN_ID&limit=50&offset=0" \
  -H "$AUTH" | jq '.[].value'

# Filter by severity
curl -s "http://localhost/api/v1/findings?scan_id=$SCAN_ID&severity=critical" \
  -H "$AUTH" | jq length

# Search findings
curl -s "http://localhost/api/v1/findings?scan_id=$SCAN_ID&search=admin" \
  -H "$AUTH" | jq '.[].value'

# Finding stats
curl -s "http://localhost/api/v1/findings/stats?scan_id=$SCAN_ID" -H "$AUTH" | jq

# MITRE heatmap
curl -s "http://localhost/api/v1/mitre/heatmap/$SCAN_ID" -H "$AUTH" | jq

# Credential leaks
curl -s "http://localhost/api/v1/credentials?scan_id=$SCAN_ID" -H "$AUTH" | jq

# Agent progress
curl -s "http://localhost/api/v1/agents?scan_id=$SCAN_ID" -H "$AUTH" | jq '.[].status'
```

## Scan Diff & History

```bash
# Get latest diff for a scan
curl -s "http://localhost/api/v1/history/diff/$SCAN_ID" -H "$AUTH" | jq

# Compare two specific scans
curl -s "http://localhost/api/v1/history/diff/$SCAN_ID/vs/$PREV_SCAN_ID" -H "$AUTH" | jq

# List scan history for a target
curl -s "http://localhost/api/v1/history/target/$TARGET_ID" -H "$AUTH" | jq
```

## Notifications

```bash
# Configure Slack notifications
curl -X POST "http://localhost/api/v1/notifications/$PROJ_ID/channels" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "channel_type": "slack",
    "config": {"webhook_url": "https://hooks.slack.com/services/T.../B.../xxx"},
    "subscribed_events": ["critical_finding", "subdomain_takeover", "scan_complete", "approval_needed"]
  }'

# Configure Discord
curl -X POST "http://localhost/api/v1/notifications/$PROJ_ID/channels" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "channel_type": "discord",
    "config": {"webhook_url": "https://discord.com/api/webhooks/..."},
    "subscribed_events": ["critical_finding", "scan_complete"]
  }'
```

## Scope Import

```bash
# Import from HackerOne
curl -X POST "http://localhost/api/v1/scope/$PROJ_ID/import/hackerone?program_handle=github" \
  -H "$AUTH"

# Import from Bugcrowd
curl -X POST "http://localhost/api/v1/scope/$PROJ_ID/import/bugcrowd?program_slug=tesla" \
  -H "$AUTH"
```

## Reports

```bash
# Generate report
curl -X POST http://localhost/api/v1/reports/generate \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"scan_id\": \"$SCAN_ID\", \"report_type\": \"executive\"}"

# List reports
curl -s http://localhost/api/v1/reports -H "$AUTH" | jq
```

## API Keys (for external services)

```bash
# Add Shodan API key (encrypted at rest)
curl -X POST http://localhost/api/v1/settings/api-keys \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"service_name": "shodan", "api_key": "YOUR_SHODAN_KEY"}'

# Verify key is valid
curl -X POST "http://localhost/api/v1/settings/api-keys/$KEY_ID/verify" -H "$AUTH"
```

## WebSocket (real-time events)

```javascript
// Connect to scan events
const ws = new WebSocket(`ws://localhost/ws/scan/${scanId}?token=${accessToken}`);

ws.onmessage = (event) => {
  const { event: type, data } = JSON.parse(event.data);
  // Events: agent.progress, agent.finding, gate.ready, scan.complete
};

// Approve gate via WebSocket
ws.send(JSON.stringify({
  action: "approve_gate",
  gate_number: 1,
  decision: "approved"
}));
```

## Health Check

```bash
curl http://localhost/api/health
# {"status": "healthy", "version": "0.9.0"}
```

## Interactive API Docs

- Swagger UI: http://localhost/api/docs
- ReDoc: http://localhost/api/redoc

## Scan Profiles

```bash
# Fire-and-forget (no gates, full speed)
curl -X POST http://localhost/api/v1/scans \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"target_id\": \"$TARGET_ID\", \"profile\": \"bounty\"}"

# Passive only (OSINT, no active probing)
curl -X POST http://localhost/api/v1/scans \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"target_id\": \"$TARGET_ID\", \"profile\": \"passive_only\"}"

# Stealth (no vuln scanning)
curl -X POST http://localhost/api/v1/scans \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"target_id\": \"$TARGET_ID\", \"profile\": \"stealth\"}"
```

## Finding Triage

```bash
# Confirm a finding
curl -X PATCH "http://localhost/api/v1/findings/$FINDING_ID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"verification_status": "confirmed"}'

# Override severity
curl -X PATCH "http://localhost/api/v1/findings/$FINDING_ID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"severity_override": "low", "severity_override_reason": "Behind WAF"}'

# Mark false positive
curl -X PATCH "http://localhost/api/v1/findings/$FINDING_ID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"verification_status": "false_positive"}'
```

## CSV Export

```bash
# Export all findings
curl -s "http://localhost/api/v1/findings/export/csv?scan_id=$SCAN_ID" \
  -H "$AUTH" -o findings.csv

# Export critical only, excluding false positives
curl -s "http://localhost/api/v1/findings/export/csv?scan_id=$SCAN_ID&severity=critical&is_false_positive=false" \
  -H "$AUTH" -o critical.csv
```

## Single-Finding Retest

```bash
# Retest after client patches a CVE
curl -X POST "http://localhost/api/v1/findings/$FINDING_ID/retest" -H "$AUTH"
# Returns: {"status":"retest_queued","template":"CVE-2024-1234","target":"https://admin.target.com"}
```

## Health Check

```bash
curl http://localhost/api/health
# Returns: {"status":"ok","services":{"postgresql":"ok","redis":"ok"}}
```
