import { useState, useEffect, useRef } from "react";

const C = {
  bg: "#0a0e17", bgCard: "#111827", bgHover: "#1a2236", bgSurface: "#0d1321",
  border: "#1e2a3a", borderActive: "#3b82f6",
  text: "#e2e8f0", muted: "#64748b", dim: "#475569",
  accent: "#3b82f6", accentGlow: "rgba(59,130,246,0.15)",
  green: "#22c55e", greenDim: "rgba(34,197,94,0.15)",
  red: "#ef4444", redDim: "rgba(239,68,68,0.15)",
  orange: "#f59e0b", orangeDim: "rgba(245,158,11,0.15)",
  purple: "#a855f7", purpleDim: "rgba(168,85,247,0.15)",
  cyan: "#06b6d4", cyanDim: "rgba(6,182,212,0.15)",
  yellow: "#eab308", yellowDim: "rgba(234,179,8,0.15)",
};

const mono = "'JetBrains Mono', monospace";
const sevColor = s => ({ critical: C.red, high: C.orange, medium: C.yellow, low: C.green }[s] || C.dim);
const sevBg = s => ({ critical: C.redDim, high: C.orangeDim, medium: C.yellowDim, low: C.greenDim }[s] || "transparent");
const statColor = s => ({ completed: C.green, running: C.accent, self_correcting: C.yellow, pending_approval: C.orange, error_resolved: C.cyan, error: C.red, pending: C.dim }[s] || C.dim);
const statLabel = s => ({ completed: "Completed", running: "Running", self_correcting: "Self-Correcting", pending_approval: "Awaiting Approval", error_resolved: "Error → Fixed", error: "Error", pending: "Queued" }[s] || s);

// ─── HEALTH EVENT LOG ────────────────────────────────────────────────
const HEALTH_EVENTS = [
  {
    id: 1, agent: "Dir/File Discovery", icon: "📂", time: "14:32:07",
    type: "anomaly_detected", severity: "warning",
    title: "Custom 404 Detected",
    detail: "Target returns HTTP 200 with identical 4,242-byte response body for all non-existent paths. 847/850 initial responses have the same content-length.",
    raw: "ffuf -w wordlist.txt -u https://target.com/FUZZ → 847 hits, all size:4242",
  },
  {
    id: 2, agent: "Dir/File Discovery", icon: "📂", time: "14:32:08",
    type: "self_correction", severity: "info",
    title: "Auto-Fix: Applying content-length filter",
    detail: "Re-running ffuf with size filter to exclude baseline 404 response.",
    raw: "ffuf -w wordlist.txt -u https://target.com/FUZZ -mc all -fs 4242 -fc 302,400,429",
  },
  {
    id: 3, agent: "Dir/File Discovery", icon: "📂", time: "14:33:41",
    type: "correction_success", severity: "success",
    title: "Self-Correction Successful — 5 real results found",
    detail: "After filtering size 4242, discovered 5 legitimate endpoints with distinct response sizes.",
    results: [
      { path: "/admin/", status: 200, size: "12,847 B", note: "WordPress admin login panel" },
      { path: "/backup.sql.gz", status: 200, size: "342,819 B", note: "Database backup exposed!" },
      { path: "/api/v1/docs", status: 301, size: "→ /api/v1/docs/", note: "Swagger/OpenAPI docs" },
      { path: "/.env", status: 200, size: "1,203 B", note: "Environment file with credentials" },
      { path: "/phpmyadmin/", status: 200, size: "8,412 B", note: "phpMyAdmin interface" },
    ],
  },
  {
    id: 4, agent: "Port & Service Agent", icon: "🔌", time: "14:28:15",
    type: "anomaly_detected", severity: "warning",
    title: "Firewall Dropping SYN Probes",
    detail: "Initial SYN scan returned 0 results on first 1000 ports. Target appears to have a stateful firewall dropping all unsolicited SYN packets.",
    raw: "nmap -sS -T4 --top-ports 1000 target.com → 0 open, 0 closed, 1000 filtered",
  },
  {
    id: 5, agent: "Port & Service Agent", icon: "🔌", time: "14:28:16",
    type: "self_correction", severity: "info",
    title: "Auto-Fix: Switching to Connect scan with host discovery skip",
    detail: "Retrying with TCP Connect scan (-sT) and -Pn to skip host discovery. Also adding --version-intensity 2 for lighter fingerprinting.",
    raw: "nmap -sT -Pn --version-intensity 2 --top-ports 1000 target.com",
  },
  {
    id: 6, agent: "Port & Service Agent", icon: "🔌", time: "14:30:42",
    type: "correction_success", severity: "success",
    title: "Self-Correction Successful — 23 open ports discovered",
    detail: "Connect scan bypassed firewall filtering. Discovered 23 open ports including critical services.",
    results: [
      { path: "22/tcp", status: "open", size: "SSH", note: "OpenSSH 7.4 — outdated, CVE candidates" },
      { path: "443/tcp", status: "open", size: "HTTPS", note: "nginx 1.18.0" },
      { path: "8443/tcp", status: "open", size: "HTTPS", note: "Admin panel on non-standard port" },
      { path: "3306/tcp", status: "open", size: "MySQL", note: "MySQL 5.7 — exposed to internet!" },
    ],
  },
  {
    id: 7, agent: "Subdomain Agent", icon: "🌐", time: "14:22:33",
    type: "anomaly_detected", severity: "warning",
    title: "DNS Wildcard Detected",
    detail: "*.target.com resolves to 203.0.113.50. Random subdomains like xyzrandom123.target.com return a valid A record. This will cause massive false positives in subdomain enumeration.",
    raw: "dig xyzrandom123456.target.com A → 203.0.113.50",
  },
  {
    id: 8, agent: "Subdomain Agent", icon: "🌐", time: "14:22:34",
    type: "self_correction", severity: "info",
    title: "Auto-Fix: Filtering wildcard IP + using response differentiation",
    detail: "Filtering out all subdomains resolving to wildcard IP 203.0.113.50 unless their HTTP response differs (different status code, content-length, or title). Also reported wildcard itself as a finding.",
    raw: "puredns resolve subs.txt --wildcard-tests 10 --wildcard-batch 500",
  },
  {
    id: 9, agent: "Subdomain Agent", icon: "🌐", time: "14:24:18",
    type: "correction_success", severity: "success",
    title: "Self-Correction Successful — 47 real subdomains after wildcard filtering",
    detail: "Filtered 2,340 wildcard responses down to 47 subdomains with unique HTTP responses.",
    results: [],
  },
  {
    id: 10, agent: "Credential Leak Agent", icon: "🔑", time: "14:25:01",
    type: "anomaly_detected", severity: "warning",
    title: "DeHashed API Rate Limited (429)",
    detail: "Hit rate limit after 15 queries. 19 more email addresses pending lookup.",
    raw: "HTTP 429 Too Many Requests — retry-after: 60",
  },
  {
    id: 11, agent: "Credential Leak Agent", icon: "🔑", time: "14:25:02",
    type: "self_correction", severity: "info",
    title: "Auto-Fix: Switching to LeakCheck API + queuing DeHashed with backoff",
    detail: "Routing remaining 19 queries through LeakCheck API. DeHashed queries queued with 60s exponential backoff.",
    raw: "Parallel: LeakCheck (19 queries) + DeHashed backoff queue (retry in 60s)",
  },
  {
    id: 12, agent: "Credential Leak Agent", icon: "🔑", time: "14:26:45",
    type: "correction_success", severity: "success",
    title: "Self-Correction Successful — All 34 emails checked across 2 providers",
    detail: "LeakCheck returned results for 19 remaining emails. DeHashed resumed after cooldown. Cross-referenced for duplicates.",
    results: [],
  },
  {
    id: 13, agent: "Web Recon Agent", icon: "🔍", time: "14:31:10",
    type: "anomaly_detected", severity: "warning",
    title: "JavaScript SPA Detected — Empty DOM on initial fetch",
    detail: "GoWitness screenshot shows blank white page for 8 subdomains. These appear to be React/Vue SPAs that require JavaScript rendering to show content.",
    raw: "httpx returned 200 but body contains only <div id='root'></div>",
  },
  {
    id: 14, agent: "Web Recon Agent", icon: "🔍", time: "14:31:11",
    type: "self_correction", severity: "info",
    title: "Auto-Fix: Switching to headless Chrome rendering",
    detail: "Re-capturing screenshots with GoWitness headless Chrome mode (--chrome-path) and waiting 5s for JS render. Also extracting JS bundle URLs for JS Analysis Agent.",
    raw: "gowitness scan --screenshot-path ./screens --chrome-path /usr/bin/chromium --delay 5",
  },
  {
    id: 15, agent: "Vulnerability Agent", icon: "🛡️", time: "14:35:22",
    type: "escalate_user", severity: "critical",
    title: "CRITICAL: Cannot auto-resolve — Nuclei scan blocked by WAF on 3 hosts",
    detail: "Cloudflare WAF is actively blocking Nuclei scan probes on admin.target.com, api.target.com, and staging.target.com. Auto-correction attempts (rate reduction, user-agent rotation) failed. Manual intervention needed.",
    raw: "nuclei -l targets.txt -t cves/ → 403 Forbidden on 3/47 hosts after 2 retry attempts",
    options: [
      "Skip these 3 hosts and continue",
      "Use WAF-bypass templates (slower, stealthier)",
      "Route through proxy/VPN and retry",
      "Abort vulnerability scan entirely",
    ],
  },
];

const AGENTS = [
  { id: "subdomain", name: "Subdomain Agent", icon: "🌐", tools: "Subfinder, Amass, crt.sh", status: "error_resolved", findings: 47, mitre: "T1593", health: "Wildcard DNS detected → auto-filtered", progress: 100, eta: "done", currentTool: "—", log: "Filtered 2340 wildcard → 47 real subdomains" },
  { id: "port", name: "Port & Service Agent", icon: "🔌", tools: "Nmap, Naabu, httpx", status: "error_resolved", findings: 23, mitre: "T1595", health: "Firewall blocked SYN → switched to Connect scan", progress: 100, eta: "done", currentTool: "—", log: "23 open ports across 47 hosts" },
  { id: "webrecon", name: "Web Recon Agent", icon: "🔍", tools: "Wappalyzer, GoWitness", status: "self_correcting", findings: 18, mitre: "T1592", health: "SPA detected → rendering with headless Chrome", progress: 72, eta: "~3m", currentTool: "GoWitness (headless)", log: "Re-capturing 8 SPA sites with Chrome rendering..." },
  { id: "dirbrute", name: "Dir/File Discovery", icon: "📂", tools: "ffuf, feroxbuster", status: "error_resolved", findings: 5, mitre: "T1190", health: "Custom 404 detected → filtered by content-length", progress: 100, eta: "done", currentTool: "—", log: "5 real results after -fs 4242 filter" },
  { id: "vuln", name: "Vulnerability Agent", icon: "🛡️", tools: "Nuclei, custom templates", status: "error", findings: 0, mitre: "T1190", health: "WAF blocking on 3 hosts — needs user decision", progress: 15, eta: "blocked", currentTool: "nuclei (paused)", log: "Cloudflare WAF blocking on admin, api, staging" },
  { id: "credleak", name: "Credential Leak Agent", icon: "🔑", tools: "DeHashed, LeakCheck, HIBP", status: "error_resolved", findings: 34, mitre: "T1078", health: "DeHashed rate-limited → failover to LeakCheck", progress: 100, eta: "done", currentTool: "—", log: "34 emails checked, 12 with passwords" },
  { id: "threatintel", name: "Threat Intel Agent", icon: "🎯", tools: "Shodan, VT, GreyNoise", status: "completed", findings: 15, mitre: "T1190", health: "All clear — no issues", progress: 100, eta: "done", currentTool: "—", log: "15 IOCs enriched across 5 sources" },
  { id: "osint", name: "OSINT Agent", icon: "👤", tools: "theHarvester, emailfinder", status: "completed", findings: 28, mitre: "T1589", health: "All clear — no issues", progress: 100, eta: "done", currentTool: "—", log: "28 emails, 12 employees identified" },
  { id: "emailsec", name: "Email Security Agent", icon: "📧", tools: "SPF/DKIM/DMARC check", status: "completed", findings: 3, mitre: "T1566", health: "All clear — no issues", progress: 100, eta: "done", currentTool: "—", log: "SPF: soft, DKIM: ok, DMARC: missing" },
  { id: "ssl", name: "SSL/TLS Agent", icon: "🔒", tools: "sslyze, testssl.sh", status: "completed", findings: 6, mitre: "T1190", health: "All clear — no issues", progress: 100, eta: "done", currentTool: "—", log: "6 issues: TLS 1.0, weak ciphers on 3 hosts" },
  { id: "waf", name: "WAF Detection Agent", icon: "🧱", tools: "wafw00f", status: "completed", findings: 2, mitre: "T1190", health: "All clear — no issues", progress: 100, eta: "done", currentTool: "—", log: "Cloudflare detected on admin, api hosts" },
  { id: "wayback", name: "Historical Data Agent", icon: "⏳", tools: "waymore, waybackurls", status: "completed", findings: 41, mitre: "T1593", health: "All clear — no issues", progress: 100, eta: "done", currentTool: "—", log: "41 archived URLs with unique endpoints" },
];

const MITRE = [
  { id: "T1190", name: "Exploit Public-Facing App", findings: 7, severity: "critical" },
  { id: "T1133", name: "External Remote Services", findings: 3, severity: "high" },
  { id: "T1078", name: "Valid Accounts", findings: 12, severity: "critical" },
  { id: "T1566", name: "Phishing", findings: 5, severity: "medium" },
  { id: "T1195", name: "Supply Chain Compromise", findings: 2, severity: "low" },
  { id: "T1199", name: "Trusted Relationship", findings: 1, severity: "low" },
  { id: "T1189", name: "Drive-by Compromise", findings: 4, severity: "medium" },
  { id: "T1659", name: "Content Injection", findings: 3, severity: "high" },
  { id: "T1200", name: "Hardware Additions", findings: 0, severity: "none" },
  { id: "T1091", name: "Removable Media", findings: 0, severity: "none" },
  { id: "T1669", name: "Wi-Fi Networks", findings: 0, severity: "none" },
];

const FINDINGS = [
  { value: "admin.target.com", detail: "HTTP 200 — Login Panel Detected", severity: "high", mitre: "T1078", agent: "Subdomain Agent" },
  { value: "target.com:8443", detail: "OpenSSH 7.4 — Outdated", severity: "critical", mitre: "T1133", agent: "Port & Service" },
  { value: "admin@target.com", detail: "12 leaked creds found (3 plaintext)", severity: "critical", mitre: "T1078", agent: "Cred Leak Agent" },
  { value: "CVE-2024-3400", detail: "PAN-OS Command Injection", severity: "critical", mitre: "T1190", agent: "Threat Intel" },
  { value: "target.com", detail: "Missing DMARC — Spoofable", severity: "high", mitre: "T1566", agent: "Email Security" },
  { value: "/admin/", detail: "WordPress admin panel exposed (found after custom-404 filter)", severity: "high", mitre: "T1078", agent: "Dir/File Discovery" },
  { value: "/.env", detail: "Environment file with DB credentials exposed", severity: "critical", mitre: "T1078", agent: "Dir/File Discovery" },
  { value: "/backup.sql.gz", detail: "342KB database backup downloadable", severity: "critical", mitre: "T1190", agent: "Dir/File Discovery" },
  { value: "staging.target.com", detail: "TLS 1.0 enabled — Weak ciphers", severity: "medium", mitre: "T1190", agent: "SSL/TLS Agent" },
  { value: "/api/v1/debug", detail: "Historical debug endpoint in Wayback", severity: "medium", mitre: "T1190", agent: "Historical Data" },
];

// ─── COMPONENTS ──────────────────────────────────────────────────────

function Sidebar({ view, setView }) {
  const items = [
    { id: "dashboard", label: "Dashboard", icon: "◆" },
    { id: "agents", label: "Agent Orchestration", icon: "⬡" },
    { id: "health", label: "Agent Health Feed", icon: "♡" },
    { id: "findings", label: "Findings", icon: "◈" },
    { id: "mitre", label: "MITRE ATT&CK", icon: "◉" },
    { id: "credentials", label: "Credentials", icon: "◎" },
    { id: "flow", label: "Recon Flow", icon: "▷" },
    { id: "divider" },
    { id: "scope", label: "Scope Control", icon: "⊘" },
    { id: "reports", label: "Reports", icon: "⊞" },
    { id: "history", label: "Scan History", icon: "⊡" },
    { id: "divider2" },
    { id: "chat", label: "AI Copilot Chat", icon: "⊹" },
    { id: "notifications", label: "Notifications", icon: "⊕" },
    { id: "settings", label: "Settings", icon: "⊙" },
  ];
  return (
    <div style={{ width: 220, minHeight: "100vh", background: C.bgSurface, borderRight: `1px solid ${C.border}`, flexShrink: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "20px 18px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${C.accent}, ${C.cyan})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 800, color: "#fff" }}>RS</div>
        <div>
          <div style={{ fontFamily: mono, fontSize: 12.5, fontWeight: 700, color: C.text, letterSpacing: "0.5px" }}>RECON SENTINEL</div>
          <div style={{ fontSize: 9.5, color: C.muted, letterSpacing: "1px" }}>AI-POWERED RECON</div>
        </div>
      </div>
      <div style={{ padding: "12px 10px", flex: 1 }}>
        {items.map(item => item.id.startsWith("divider") ? (
          <div key={item.id} style={{ borderBottom: `1px solid ${C.border}`, margin: "8px 4px" }} />
        ) : (
          <div key={item.id} onClick={() => setView(item.id)} style={{
            padding: "10px 12px", borderRadius: 8, marginBottom: 2, cursor: "pointer", display: "flex", alignItems: "center", gap: 10,
            background: view === item.id ? C.accentGlow : "transparent",
            border: view === item.id ? `1px solid ${C.accent}33` : "1px solid transparent",
          }}>
            <span style={{ fontSize: 13, opacity: view === item.id ? 1 : 0.5 }}>{item.icon}</span>
            <span style={{ fontSize: 12, fontWeight: view === item.id ? 600 : 400, color: view === item.id ? C.text : C.muted, fontFamily: mono }}>{item.label}</span>
            {item.id === "health" && (
              <span style={{ marginLeft: "auto", fontSize: 9, padding: "2px 6px", borderRadius: 10, background: C.yellowDim, color: C.yellow, fontFamily: mono, fontWeight: 700 }}>4</span>
            )}
            {item.id === "chat" && (
              <span style={{ marginLeft: "auto", fontSize: 9, padding: "2px 6px", borderRadius: 10, background: C.cyanDim, color: C.cyan, fontFamily: mono, fontWeight: 700 }}>LIVE</span>
            )}
            {item.id === "scope" && (
              <span style={{ marginLeft: "auto", fontSize: 9, padding: "2px 6px", borderRadius: 10, background: C.greenDim, color: C.green, fontFamily: mono, fontWeight: 700 }}>SET</span>
            )}
            {item.id === "history" && (
              <span style={{ marginLeft: "auto", fontSize: 9, padding: "2px 6px", borderRadius: 10, background: C.purpleDim, color: C.purple, fontFamily: mono, fontWeight: 700 }}>3</span>
            )}
          </div>
        ))}
      </div>
      <div style={{ padding: "14px", borderTop: `1px solid ${C.border}` }}>
        <div style={{ padding: "10px 12px", borderRadius: 8, background: C.greenDim, border: `1px solid ${C.green}33`, display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, boxShadow: `0 0 8px ${C.green}` }} />
          <span style={{ fontSize: 10.5, color: C.green, fontFamily: mono }}>SCAN ACTIVE</span>
        </div>
      </div>
    </div>
  );
}

function Header({ target, setTarget, inputType, setInputType, showPalette, setShowPalette }) {
  const [scanning, setScanning] = useState(true);
  const [showContext, setShowContext] = useState(false);

  const targetContext = {
    ip: "203.0.113.42", asn: "AS13335 — Cloudflare, Inc.", cdn: "Cloudflare (detected)", registrar: "GoDaddy",
    created: "2015-03-22", expires: "2026-03-22", nameservers: "ns1.cloudflare.com, ns2.cloudflare.com",
    techStack: ["nginx 1.18", "WordPress 6.x", "PHP 8.2", "MySQL 5.7", "jQuery 3.6"],
    previousScans: 3,
  };

  return (
    <div style={{ borderBottom: `1px solid ${C.border}`, background: C.bgSurface }}>
      <div style={{ padding: "12px 24px", display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ display: "flex", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          {[["URL / Domain","url"],["IP / CIDR","ip"]].map(([l,v]) => (
            <button key={v} onClick={() => setInputType(v)} style={{ padding: "7px 13px", border: "none", cursor: "pointer", background: inputType===v ? C.accent : "transparent", color: inputType===v ? "#fff" : C.muted, fontSize: 11, fontFamily: mono, fontWeight: 600 }}>{l}</button>
          ))}
        </div>
        <div style={{ flex: 1, position: "relative" }}>
          <input value={target} onChange={e=>setTarget(e.target.value)} placeholder={inputType==="url" ? "Enter domain..." : "Enter IP/CIDR..."}
            style={{ width: "100%", padding: "8px 14px", paddingRight: 80, borderRadius: 8, border: `1px solid ${C.border}`, background: C.bgCard, color: C.text, fontSize: 12, fontFamily: mono, outline: "none", boxSizing: "border-box" }} />
          <button onClick={() => setShowContext(!showContext)} style={{ position: "absolute", right: 6, top: 4, padding: "4px 10px", borderRadius: 5, border: `1px solid ${C.border}`, background: showContext ? C.accentGlow : "transparent", color: showContext ? C.accent : C.dim, fontSize: 9, fontFamily: mono, cursor: "pointer", fontWeight: 600 }}>
            {showContext ? "▲ WHOIS" : "▼ WHOIS"}
          </button>
        </div>
        <select style={{ padding: "8px 11px", borderRadius: 8, border: `1px solid ${C.border}`, background: C.bgCard, color: C.text, fontSize: 11, fontFamily: mono, outline: "none", cursor: "pointer" }}>
          <option>Full Recon</option><option>Passive Only</option><option>Quick Assessment</option><option>Red Team Stealth</option>
        </select>
        <button onClick={()=>setShowPalette(true)} title="Ctrl+K" style={{ padding: "8px 10px", borderRadius: 8, border: `1px solid ${C.border}`, background: "transparent", color: C.muted, fontSize: 11, fontFamily: mono, cursor: "pointer" }}>⌘K</button>
        <button onClick={()=>setScanning(!scanning)} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: scanning ? C.red : `linear-gradient(135deg, ${C.accent}, ${C.cyan})`, color: "#fff", fontSize: 12, fontWeight: 700, fontFamily: mono, boxShadow: `0 0 20px ${scanning ? C.red : C.accent}40` }}>
          {scanning ? "⏹ STOP" : "▶ LAUNCH"}
        </button>
      </div>

      {/* P1: Target Context Panel */}
      {showContext && (
        <div style={{ padding: "0 24px 14px", display: "flex", gap: 10, flexWrap: "wrap" }}>
          {[
            ["IP", targetContext.ip, C.cyan],
            ["ASN", targetContext.asn, C.purple],
            ["CDN", targetContext.cdn, C.orange],
            ["Registrar", targetContext.registrar, C.text],
            ["Created", targetContext.created, C.text],
            ["Expires", targetContext.expires, targetContext.expires.includes("2026") ? C.orange : C.text],
            ["NS", targetContext.nameservers, C.text],
          ].map(([k, v, col]) => (
            <div key={k} style={{ padding: "6px 10px", borderRadius: 6, background: C.bgCard, border: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 9, color: C.muted, fontFamily: mono, fontWeight: 700, letterSpacing: "0.3px" }}>{k}:</span>
              <span style={{ fontSize: 10, color: col, fontFamily: mono }}>{v}</span>
            </div>
          ))}
          <div style={{ padding: "6px 10px", borderRadius: 6, background: C.bgCard, border: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 9, color: C.muted, fontFamily: mono, fontWeight: 700 }}>TECH:</span>
            <div style={{ display: "flex", gap: 4 }}>
              {targetContext.techStack.map(t => (
                <span key={t} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: C.purpleDim, color: C.purple, fontFamily: mono }}>{t}</span>
              ))}
            </div>
          </div>
          <div style={{ padding: "6px 10px", borderRadius: 6, background: C.accentGlow, border: `1px solid ${C.accent}33`, display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 9, color: C.accent, fontFamily: mono, fontWeight: 700 }}>PREV SCANS: {targetContext.previousScans}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color, icon, sub }) {
  return (
    <div style={{ background: C.bgCard, borderRadius: 10, padding: "16px 18px", border: `1px solid ${C.border}`, flex: 1, minWidth: 140 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <span style={{ fontSize: 10, color: C.muted, fontFamily: mono, letterSpacing: "0.5px" }}>{label}</span>
        <span style={{ fontSize: 14 }}>{icon}</span>
      </div>
      <div style={{ fontSize: 26, fontWeight: 800, color: color || C.text, fontFamily: mono }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: C.green, marginTop: 3, fontFamily: mono }}>{sub}</div>}
    </div>
  );
}

// ─── AGENT HEALTH FEED (NEW!) ───────────────────────────────────────

function HealthFeedView() {
  const [filter, setFilter] = useState("all");
  const [expandedId, setExpandedId] = useState(null);
  const eventTypes = { all: "All Events", anomaly_detected: "Anomalies", self_correction: "Corrections", correction_success: "Resolved", escalate_user: "Needs Action" };
  const filtered = filter === "all" ? HEALTH_EVENTS : HEALTH_EVENTS.filter(e => e.type === filter);

  const typeIcon = t => ({ anomaly_detected: "⚠️", self_correction: "🔧", correction_success: "✅", escalate_user: "🚨" }[t] || "ℹ️");
  const typeBorder = t => ({ anomaly_detected: C.yellow, self_correction: C.accent, correction_success: C.green, escalate_user: C.red }[t] || C.dim);
  const typeBg = t => ({ anomaly_detected: C.yellowDim, self_correction: C.accentGlow, correction_success: C.greenDim, escalate_user: C.redDim }[t] || "transparent");

  const needsAction = HEALTH_EVENTS.filter(e => e.type === "escalate_user").length;
  const corrected = HEALTH_EVENTS.filter(e => e.type === "correction_success").length;

  return (
    <div style={{ padding: 24 }}>
      {/* Header Stats */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 800, color: C.text, fontFamily: mono }}>Agent Health & Self-Correction Feed</div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>Real-time anomaly detection, auto-fix timeline, and escalation log</div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <div style={{ padding: "8px 14px", borderRadius: 8, background: C.greenDim, border: `1px solid ${C.green}33`, textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 800, color: C.green, fontFamily: mono }}>{corrected}</div>
            <div style={{ fontSize: 9, color: C.green, fontFamily: mono }}>AUTO-FIXED</div>
          </div>
          <div style={{ padding: "8px 14px", borderRadius: 8, background: needsAction > 0 ? C.redDim : C.greenDim, border: `1px solid ${needsAction > 0 ? C.red : C.green}33`, textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 800, color: needsAction > 0 ? C.red : C.green, fontFamily: mono }}>{needsAction}</div>
            <div style={{ fontSize: 9, color: needsAction > 0 ? C.red : C.green, fontFamily: mono }}>NEEDS ACTION</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 6, marginBottom: 18 }}>
        {Object.entries(eventTypes).map(([k, v]) => (
          <button key={k} onClick={() => setFilter(k)} style={{
            padding: "6px 12px", borderRadius: 6, border: `1px solid ${filter===k ? C.accent : C.border}`, cursor: "pointer",
            background: filter===k ? C.accentGlow : "transparent", color: filter===k ? C.text : C.muted,
            fontSize: 11, fontFamily: mono, fontWeight: filter===k ? 700 : 400,
          }}>{v}</button>
        ))}
      </div>

      {/* Timeline */}
      <div style={{ position: "relative" }}>
        <div style={{ position: "absolute", left: 15, top: 10, bottom: 10, width: 2, background: `${C.border}`, zIndex: 0 }} />

        {filtered.map((evt, i) => (
          <div key={evt.id} onClick={() => setExpandedId(expandedId === evt.id ? null : evt.id)} style={{
            display: "flex", gap: 16, marginBottom: 10, position: "relative", cursor: "pointer",
          }}>
            {/* Timeline dot */}
            <div style={{
              width: 32, height: 32, borderRadius: "50%", flexShrink: 0, zIndex: 1,
              background: typeBg(evt.type), border: `2px solid ${typeBorder(evt.type)}`,
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14,
            }}>{typeIcon(evt.type)}</div>

            {/* Event card */}
            <div style={{
              flex: 1, background: C.bgCard, borderRadius: 10, padding: "14px 16px",
              border: `1px solid ${expandedId === evt.id ? typeBorder(evt.type) : C.border}`,
              borderLeft: `3px solid ${typeBorder(evt.type)}`,
              transition: "all 0.2s",
            }}>
              {/* Header row */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 14 }}>{evt.icon}</span>
                <span style={{ fontSize: 11, color: C.muted, fontFamily: mono }}>{evt.agent}</span>
                <span style={{ fontSize: 10, color: C.dim, fontFamily: mono, marginLeft: "auto" }}>{evt.time}</span>
              </div>

              {/* Title */}
              <div style={{ fontSize: 13, fontWeight: 700, color: C.text, fontFamily: mono, marginBottom: 6 }}>
                {evt.title}
              </div>

              {/* Detail */}
              <div style={{ fontSize: 11.5, color: C.muted, lineHeight: 1.5 }}>
                {evt.detail}
              </div>

              {/* Expanded: raw command */}
              {expandedId === evt.id && evt.raw && (
                <div style={{
                  marginTop: 10, padding: "10px 12px", borderRadius: 6,
                  background: C.bgSurface, border: `1px solid ${C.border}`,
                  fontFamily: mono, fontSize: 10.5, color: C.cyan, lineHeight: 1.6,
                  overflowX: "auto", whiteSpace: "pre-wrap",
                }}>
                  <span style={{ color: C.dim }}>$ </span>{evt.raw}
                </div>
              )}

              {/* Expanded: results table */}
              {expandedId === evt.id && evt.results && evt.results.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 10, color: C.muted, fontFamily: mono, marginBottom: 6, letterSpacing: "0.5px" }}>DISCOVERED ENDPOINTS:</div>
                  {evt.results.map((r, j) => (
                    <div key={j} style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "8px 10px",
                      borderRadius: 6, background: C.bgSurface, marginBottom: 4,
                      borderLeft: `2px solid ${r.note && r.note.includes("!") ? C.red : C.green}`,
                    }}>
                      <span style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: mono, minWidth: 140 }}>{r.path}</span>
                      <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: r.status === 200 || r.status === "open" ? C.greenDim : C.accentGlow, color: r.status === 200 || r.status === "open" ? C.green : C.accent, fontFamily: mono, fontWeight: 600 }}>
                        {r.status}
                      </span>
                      <span style={{ fontSize: 10, color: C.dim, fontFamily: mono }}>{r.size}</span>
                      <span style={{ fontSize: 10.5, color: r.note && r.note.includes("!") ? C.orange : C.muted, flex: 1, textAlign: "right" }}>{r.note}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Escalation: user action buttons */}
              {evt.type === "escalate_user" && evt.options && (
                <div style={{ marginTop: 12, display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {evt.options.map((opt, j) => (
                    <button key={j} style={{
                      padding: "7px 14px", borderRadius: 6, cursor: "pointer", fontSize: 11, fontFamily: mono, fontWeight: 600,
                      background: j === 0 ? C.green : j === 1 ? C.accentGlow : "transparent",
                      color: j === 0 ? "#fff" : j === 1 ? C.accent : C.muted,
                      border: `1px solid ${j === 0 ? C.green : j === 1 ? C.accent + "44" : C.border}`,
                    }}>{opt}</button>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      <style>{`@keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.4 } }`}</style>
    </div>
  );
}

// ─── DASHBOARD ────────────────────────────────────────────────────────

function DashboardView() {
  const corrected = AGENTS.filter(a => a.status === "error_resolved").length;
  const issues = AGENTS.filter(a => a.status === "error" || a.status === "self_correcting").length;

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        <Stat label="SUBDOMAINS" value="47" color={C.cyan} icon="🌐" sub="↑ 5 since last" />
        <Stat label="OPEN PORTS" value="23" color={C.accent} icon="🔌" />
        <Stat label="VULNS" value="18" color={C.red} icon="🛡️" sub="↑ 3 new" />
        <Stat label="LEAKED CREDS" value="34" color={C.orange} icon="🔑" sub="4 plaintext!" />
        <Stat label="AGENT HEALTH" value={`${corrected} fixed`} color={issues > 0 ? C.yellow : C.green} icon="♡" sub={issues > 0 ? `${issues} issue(s) active` : "All clear"} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Agent Status with health indicators */}
        <div style={{ background: C.bgCard, borderRadius: 10, padding: 18, border: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 14, fontFamily: mono }}>AGENT STATUS & HEALTH</div>
          {AGENTS.slice(0, 8).map(a => (
            <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 8px", borderRadius: 6, background: C.bgSurface, marginBottom: 4 }}>
              <span style={{ fontSize: 13 }}>{a.icon}</span>
              <span style={{ fontSize: 11, color: C.text, flex: 1, fontFamily: mono }}>{a.name}</span>
              {/* Health indicator */}
              {a.status === "error_resolved" && (
                <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: C.cyanDim, color: C.cyan, fontFamily: mono, fontWeight: 600 }}>SELF-FIXED</span>
              )}
              {a.status === "self_correcting" && (
                <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: C.yellowDim, color: C.yellow, fontFamily: mono, fontWeight: 600, animation: "pulse 1.5s infinite" }}>CORRECTING</span>
              )}
              {a.status === "error" && (
                <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: C.redDim, color: C.red, fontFamily: mono, fontWeight: 600 }}>ACTION NEEDED</span>
              )}
              <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: statColor(a.status) + "22", color: statColor(a.status), fontFamily: mono, fontWeight: 600 }}>
                {a.findings > 0 ? a.findings : statLabel(a.status)}
              </span>
            </div>
          ))}
        </div>

        {/* Latest Health Events (mini feed) */}
        <div style={{ background: C.bgCard, borderRadius: 10, padding: 18, border: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 14, fontFamily: mono }}>RECENT AGENT CORRECTIONS</div>
          {HEALTH_EVENTS.filter(e => e.type === "correction_success" || e.type === "escalate_user").slice(0, 5).map(evt => (
            <div key={evt.id} style={{
              padding: "8px 10px", borderRadius: 6, background: C.bgSurface, marginBottom: 4,
              borderLeft: `3px solid ${evt.type === "escalate_user" ? C.red : C.green}`,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                <span style={{ fontSize: 12 }}>{evt.icon}</span>
                <span style={{ fontSize: 11, fontWeight: 700, color: C.text, fontFamily: mono, flex: 1 }}>{evt.title.length > 45 ? evt.title.slice(0, 45) + "..." : evt.title}</span>
                <span style={{ fontSize: 9.5, color: C.dim, fontFamily: mono }}>{evt.time}</span>
              </div>
              <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.4 }}>{evt.detail.length > 100 ? evt.detail.slice(0, 100) + "..." : evt.detail}</div>
            </div>
          ))}
        </div>
      </div>
      <style>{`@keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.4 } }`}</style>
    </div>
  );
}

// ─── AGENT ORCHESTRATION ─────────────────────────────────────────────

function AgentsView() {
  const [expanded, setExpanded] = useState(null);
  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 800, color: C.text, fontFamily: mono }}>AI Agent Orchestration</div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>Human-in-the-loop • LangGraph FSM • Self-correcting agents</div>
        </div>
      </div>

      {/* Escalation banner if any */}
      {AGENTS.some(a => a.status === "error") && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}44`, borderRadius: 10, padding: 16, marginBottom: 16, display: "flex", alignItems: "center", gap: 14 }}>
          <span style={{ fontSize: 22 }}>🚨</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.red, fontFamily: mono }}>AGENT ESCALATION — User Decision Required</div>
            <div style={{ fontSize: 11.5, color: C.muted, marginTop: 3 }}>Vulnerability Agent blocked by WAF on 3 hosts. Auto-correction failed after 2 attempts. See Agent Health Feed for details and options.</div>
          </div>
          <button style={{ padding: "8px 16px", borderRadius: 8, border: "none", cursor: "pointer", background: C.red, color: "#fff", fontSize: 11, fontWeight: 700, fontFamily: mono }}>VIEW & RESOLVE</button>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 10 }}>
        {AGENTS.map(a => (
          <div key={a.id} onClick={() => setExpanded(expanded===a.id ? null : a.id)} style={{
            background: C.bgCard, borderRadius: 10, padding: 14, cursor: "pointer",
            border: `1px solid ${expanded===a.id ? C.accent : a.status === "error" ? C.red + "44" : C.border}`,
            opacity: a.status === "pending" ? 0.45 : 1, transition: "all 0.2s",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: 18 }}>{a.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11.5, fontWeight: 700, color: C.text, fontFamily: mono }}>{a.name}</div>
                <div style={{ fontSize: 9.5, color: C.dim }}>{a.tools}</div>
              </div>
              {(a.status === "running" || a.status === "self_correcting") && (
                <div style={{ width: 9, height: 9, borderRadius: "50%", background: statColor(a.status), boxShadow: `0 0 10px ${statColor(a.status)}`, animation: "pulse 1.5s infinite" }} />
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 9.5, padding: "2px 7px", borderRadius: 4, background: statColor(a.status)+"22", color: statColor(a.status), fontFamily: mono, fontWeight: 600 }}>{statLabel(a.status)}</span>
              <span style={{ fontSize: 9.5, padding: "2px 6px", borderRadius: 3, background: C.purpleDim, color: C.purple, fontFamily: mono }}>{a.mitre}</span>
              {a.findings > 0 && <span style={{ fontSize: 12, fontWeight: 800, color: C.text, fontFamily: mono }}>{a.findings}</span>}
            </div>

            {/* Health note inline */}
            {a.health !== "All clear — no issues" && (
              <div style={{
                marginTop: 8, padding: "6px 8px", borderRadius: 5, fontSize: 10, lineHeight: 1.4,
                background: a.status === "error" ? C.redDim : C.cyanDim,
                color: a.status === "error" ? C.red : C.cyan,
                fontFamily: mono, borderLeft: `2px solid ${a.status === "error" ? C.red : C.cyan}`,
              }}>
                {a.status === "error" ? "🚨 " : "🔧 "}{a.health}
              </div>
            )}

            {/* P1: Progress bar */}
            {a.progress < 100 && (
              <div style={{ marginTop: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                  <span style={{ fontSize: 9, color: C.muted, fontFamily: mono }}>{a.currentTool}</span>
                  <span style={{ fontSize: 9, color: a.eta === "blocked" ? C.red : C.muted, fontFamily: mono }}>{a.eta === "blocked" ? "BLOCKED" : `ETA: ${a.eta}`}</span>
                </div>
                <div style={{ width: "100%", height: 4, borderRadius: 2, background: C.bgSurface }}>
                  <div style={{
                    width: `${a.progress}%`, height: "100%", borderRadius: 2,
                    background: a.status === "error" ? C.red : a.status === "self_correcting" ? C.yellow : C.accent,
                    transition: "width 0.5s",
                  }} />
                </div>
                <div style={{ fontSize: 9, color: C.dim, fontFamily: mono, marginTop: 3 }}>{a.progress}% complete</div>
              </div>
            )}

            {/* P1: Expanded detail with log */}
            {expanded === a.id && (
              <div style={{ marginTop: 8, padding: "8px 8px", borderRadius: 5, background: C.bgSurface, borderTop: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 9, color: C.muted, fontFamily: mono, marginBottom: 4, letterSpacing: "0.5px" }}>LAST LOG OUTPUT:</div>
                <div style={{ fontSize: 10, color: C.cyan, fontFamily: mono, lineHeight: 1.5 }}>
                  <span style={{ color: C.dim }}>$ </span>{a.log}
                </div>
                <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
                  <button style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.border}`, background: "transparent", color: C.muted, fontSize: 9.5, fontFamily: mono, cursor: "pointer" }}>View Full Logs</button>
                  {a.status !== "completed" && a.status !== "error_resolved" && (
                    <button style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.red}44`, background: C.redDim, color: C.red, fontSize: 9.5, fontFamily: mono, cursor: "pointer" }}>Pause Agent</button>
                  )}
                  <button style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.accent}44`, background: C.accentGlow, color: C.accent, fontSize: 9.5, fontFamily: mono, cursor: "pointer" }}>Re-run Agent</button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
      <style>{`@keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.4 } }`}</style>
    </div>
  );
}

// ─── MITRE VIEW ──────────────────────────────────────────────────────

function MITREView() {
  return (
    <div style={{ padding: 24 }}>
      <div style={{ fontSize: 18, fontWeight: 800, color: C.text, marginBottom: 4, fontFamily: mono }}>MITRE ATT&CK — Initial Access (TA0001)</div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>Auto-mapped from scan findings • Severity heatmap</div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))", gap: 10 }}>
        {MITRE.map(t => {
          const int = t.findings === 0 ? 0 : Math.min(t.findings / 12, 1);
          const bg = t.severity === "none" ? C.bgCard : `${sevColor(t.severity)}${Math.round(8 + int * 25).toString(16).padStart(2,'0')}`;
          return (
            <div key={t.id} style={{ background: bg, borderRadius: 10, padding: 14, border: `1px solid ${t.severity==="none" ? C.border : sevColor(t.severity)+"44"}`, opacity: t.findings===0 ? 0.35 : 1 }}>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: sevColor(t.severity)||C.dim, fontFamily: mono, marginBottom: 5 }}>{t.id}</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 8, lineHeight: 1.3 }}>{t.name}</div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 20, fontWeight: 800, fontFamily: mono, color: t.findings > 0 ? C.text : C.dim }}>{t.findings}</span>
                {t.severity !== "none" && <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: sevBg(t.severity), color: sevColor(t.severity), fontFamily: mono, fontWeight: 700, textTransform: "uppercase" }}>{t.severity}</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── FINDINGS VIEW ───────────────────────────────────────────────────

function FindingsView() {
  const [f, setF] = useState("all");
  const [selected, setSelected] = useState(new Set());
  const [showNoteFor, setShowNoteFor] = useState(null);
  const selectAll = () => selected.size === FINDINGS.length ? setSelected(new Set()) : setSelected(new Set(FINDINGS.map((_, i) => i)));
  const toggle = (i) => { const s = new Set(selected); s.has(i) ? s.delete(i) : s.add(i); setSelected(s); };
  const data = f === "all" ? FINDINGS : FINDINGS.filter(x => x.severity === f);

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ fontSize: 18, fontWeight: 800, color: C.text, fontFamily: mono }}>All Findings ({FINDINGS.length})</div>
        <div style={{ display: "flex", gap: 5 }}>
          {["all","critical","high","medium","low"].map(x => (
            <button key={x} onClick={()=>setF(x)} style={{ padding: "5px 10px", borderRadius: 5, border: "none", cursor: "pointer", background: f===x ? (x==="all"?C.accent:sevColor(x)) : C.bgCard, color: "#fff", fontSize: 10, fontWeight: 600, fontFamily: mono, textTransform: "uppercase", opacity: f===x ? 1 : 0.4 }}>{x}</button>
          ))}
        </div>
      </div>

      {/* P1: Bulk action bar */}
      {selected.size > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderRadius: 8, background: C.accentGlow, border: `1px solid ${C.accent}33`, marginBottom: 12 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: C.accent, fontFamily: mono }}>{selected.size} selected</span>
          <div style={{ flex: 1 }} />
          <button style={{ padding: "5px 12px", borderRadius: 5, border: `1px solid ${C.dim}`, background: "transparent", color: C.muted, fontSize: 10, fontFamily: mono, cursor: "pointer", fontWeight: 600 }}>🏷 Mark False Positive</button>
          <button style={{ padding: "5px 12px", borderRadius: 5, border: `1px solid ${C.dim}`, background: "transparent", color: C.muted, fontSize: 10, fontFamily: mono, cursor: "pointer", fontWeight: 600 }}>📝 Add Note</button>
          <button style={{ padding: "5px 12px", borderRadius: 5, border: `1px solid ${C.dim}`, background: "transparent", color: C.muted, fontSize: 10, fontFamily: mono, cursor: "pointer", fontWeight: 600 }}>👤 Assign To...</button>
          <button style={{ padding: "5px 12px", borderRadius: 5, border: `1px solid ${C.accent}44`, background: C.accentGlow, color: C.accent, fontSize: 10, fontFamily: mono, cursor: "pointer", fontWeight: 600 }}>⬇ Export Selected</button>
          <button onClick={() => setSelected(new Set())} style={{ padding: "5px 8px", borderRadius: 5, border: "none", background: "transparent", color: C.dim, fontSize: 12, cursor: "pointer" }}>✕</button>
        </div>
      )}

      {/* Select all checkbox */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, padding: "0 4px" }}>
        <div onClick={selectAll} style={{ width: 16, height: 16, borderRadius: 3, border: `2px solid ${selected.size === FINDINGS.length ? C.accent : C.dim}`, background: selected.size === FINDINGS.length ? C.accent : "transparent", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: "#fff" }}>
          {selected.size === FINDINGS.length && "✓"}
        </div>
        <span style={{ fontSize: 10, color: C.muted, fontFamily: mono }}>Select all</span>
      </div>

      {data.map((x,i) => (
        <div key={i} style={{ background: C.bgCard, borderRadius: 8, padding: "10px 14px", border: `1px solid ${selected.has(i) ? C.accent : C.border}`, borderLeft: `4px solid ${sevColor(x.severity)}`, marginBottom: 5, display: "flex", alignItems: "center", gap: 12 }}>
          {/* Checkbox */}
          <div onClick={(e) => { e.stopPropagation(); toggle(i); }} style={{ width: 16, height: 16, borderRadius: 3, border: `2px solid ${selected.has(i) ? C.accent : C.dim}`, background: selected.has(i) ? C.accent : "transparent", cursor: "pointer", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: "#fff" }}>
            {selected.has(i) && "✓"}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: mono }}>{x.value}</span>
              <span style={{ fontSize: 9, padding: "2px 5px", borderRadius: 3, background: sevBg(x.severity), color: sevColor(x.severity), fontFamily: mono, fontWeight: 700, textTransform: "uppercase" }}>{x.severity}</span>
            </div>
            <div style={{ fontSize: 11, color: C.muted }}>{x.detail}</div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 3 }}>
            <div style={{ fontSize: 9.5, padding: "2px 7px", borderRadius: 3, background: C.purpleDim, color: C.purple, fontFamily: mono, fontWeight: 600 }}>{x.mitre}</div>
            <div style={{ fontSize: 9.5, color: C.dim }}>{x.agent}</div>
          </div>
          {/* Note icon */}
          <button onClick={() => setShowNoteFor(showNoteFor === i ? null : i)} style={{ padding: "4px 6px", borderRadius: 4, border: `1px solid ${C.border}`, background: "transparent", color: C.dim, fontSize: 11, cursor: "pointer" }} title="Add note">📝</button>
        </div>
      ))}
    </div>
  );
}

// ─── CREDENTIALS VIEW ────────────────────────────────────────────────

function CredentialsView() {
  const creds = [
    { email: "admin@target.com", breaches: 5, pw: 3, plain: 2, date: "2025-11-14", sev: "critical" },
    { email: "devops@target.com", breaches: 3, pw: 2, plain: 1, date: "2025-08-22", sev: "high" },
    { email: "cto@target.com", breaches: 2, pw: 1, plain: 1, date: "2025-03-15", sev: "critical" },
    { email: "hr@target.com", breaches: 7, pw: 4, plain: 0, date: "2024-12-01", sev: "medium" },
    { email: "support@target.com", breaches: 4, pw: 2, plain: 0, date: "2025-06-30", sev: "medium" },
  ];
  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 800, color: C.text, fontFamily: mono }}>Credential Leak Database</div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>DeHashed • LeakCheck • HIBP • MITRE T1078</div>
        </div>
        <button style={{ padding: "9px 16px", borderRadius: 8, border: `1px solid ${C.accent}44`, background: C.accentGlow, color: C.accent, fontSize: 11, fontWeight: 700, cursor: "pointer", fontFamily: mono }}>⬇ DOWNLOAD</button>
      </div>
      <div style={{ display: "flex", gap: 12, marginBottom: 18 }}>
        <Stat label="EMAILS" value="34" color={C.text} icon="📧" />
        <Stat label="WITH PASSWORDS" value="12" color={C.orange} icon="🔑" />
        <Stat label="PLAINTEXT" value="4" color={C.red} icon="⚠️" />
        <Stat label="REUSE DETECTED" value="6" color={C.red} icon="🔄" />
      </div>
      <div style={{ background: C.bgCard, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 1fr 80px", padding: "10px 16px", background: C.bgSurface, borderBottom: `1px solid ${C.border}`, fontSize: 9.5, color: C.muted, fontFamily: mono, fontWeight: 700 }}>
          <span>EMAIL</span><span>BREACHES</span><span>PASSWORDS</span><span>PLAINTEXT</span><span>LAST SEEN</span><span>RISK</span>
        </div>
        {creds.map((c,i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 1fr 80px", padding: "10px 16px", borderBottom: `1px solid ${C.border}22`, alignItems: "center" }}>
            <span style={{ fontSize: 11.5, color: C.text, fontFamily: mono, fontWeight: 600 }}>{c.email}</span>
            <span style={{ fontSize: 11.5, color: C.text, fontFamily: mono }}>{c.breaches}</span>
            <span style={{ fontSize: 11.5, color: c.pw>0?C.orange:C.dim, fontFamily: mono, fontWeight: 600 }}>{c.pw}</span>
            <span style={{ fontSize: 11.5, color: c.plain>0?C.red:C.dim, fontFamily: mono, fontWeight: 700 }}>{c.plain}</span>
            <span style={{ fontSize: 10.5, color: C.muted, fontFamily: mono }}>{c.date}</span>
            <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: sevBg(c.sev), color: sevColor(c.sev), fontFamily: mono, fontWeight: 700, textTransform: "uppercase", textAlign: "center" }}>{c.sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── RECON FLOW VIEW ─────────────────────────────────────────────────

function FlowView() {
  const phases = [
    { name: "PHASE 1 — PASSIVE", desc: "No direct contact. Public sources only.", model: "Haiku 4.5 ($0.015)", agents: ["Subdomain","OSINT","Email Sec","Threat Intel","Cred Leak","Wayback"], color: C.green },
    { name: "APPROVAL GATE #1", desc: "AI presents findings, recommends active scan scope.", model: "Sonnet 4.6 ($0.075)", agents: [], color: C.orange, gate: true },
    { name: "PHASE 2 — ACTIVE", desc: "Direct interaction with target. Requires approval.", model: "Haiku 4.5 (route)", agents: ["Port/Service","WAF","SSL/TLS","Cloud","Web Recon","Dir Brute","JS Analysis","API Discovery"], color: C.accent },
    { name: "APPROVAL GATE #2", desc: "AI suggests vuln scan scope based on attack surface.", model: "Sonnet 4.6 ($0.075)", agents: [], color: C.orange, gate: true },
    { name: "PHASE 3 — VULN ASSESSMENT", desc: "Active vulnerability scanning. Self-corrects on WAF/rate-limit issues.", model: "Haiku 4.5 (route)", agents: ["Nuclei Vuln Scan","Subdomain Takeover","DNS Zone Transfer"], color: C.red },
    { name: "REPORT", desc: "AI executive summary + MITRE heatmap + remediation.", model: "Sonnet 4.6 ($0.12)", agents: ["LLM Report Agent"], color: C.purple },
  ];
  return (
    <div style={{ padding: 24 }}>
      <div style={{ fontSize: 18, fontWeight: 800, color: C.text, marginBottom: 4, fontFamily: mono }}>Reconnaissance Flow</div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>LangGraph FSM • 3 phases • 2 approval gates • Self-correcting agents</div>
      <div style={{ position: "relative" }}>
        <div style={{ position: "absolute", left: 17, top: 20, bottom: 20, width: 2, background: `linear-gradient(${C.green}, ${C.accent}, ${C.red}, ${C.purple})`, opacity: 0.25 }} />
        {phases.map((p, i) => (
          <div key={i} style={{ display: "flex", gap: 16, marginBottom: 14, position: "relative" }}>
            <div style={{ width: 36, height: 36, borderRadius: "50%", flexShrink: 0, zIndex: 1, background: p.gate ? C.orangeDim : `${p.color}22`, border: `2px solid ${p.color}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: p.gate ? 14 : 12, fontWeight: 800, color: p.color, fontFamily: mono }}>
              {p.gate ? "⏸" : i === 5 ? "R" : Math.ceil((i+1)/2)}
            </div>
            <div style={{ flex: 1, background: C.bgCard, borderRadius: 10, padding: 16, border: `1px solid ${p.gate ? C.orange+"44" : C.border}`, borderLeft: `3px solid ${p.color}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <span style={{ fontSize: 12.5, fontWeight: 700, color: p.color, fontFamily: mono }}>{p.name}</span>
                <span style={{ fontSize: 9.5, padding: "2px 7px", borderRadius: 4, background: C.bgSurface, color: C.muted, fontFamily: mono }}>{p.model}</span>
              </div>
              <div style={{ fontSize: 11.5, color: C.muted, marginBottom: p.agents.length > 0 ? 10 : 0 }}>{p.desc}</div>
              {p.agents.length > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                  {p.agents.map((a,j) => <span key={j} style={{ fontSize: 9.5, padding: "3px 9px", borderRadius: 4, background: C.bgSurface, color: C.text, fontFamily: mono, border: `1px solid ${C.border}` }}>{a}</span>)}
                </div>
              )}
              {p.gate && <div style={{ marginTop: 10, padding: "8px 12px", borderRadius: 6, background: C.orangeDim, border: `1px solid ${C.orange}33`, display: "flex", alignItems: "center", gap: 8 }}><span style={{ fontSize: 13 }}>👤</span><span style={{ fontSize: 10.5, color: C.orange, fontFamily: mono }}>USER DECISION: Approve, Customize, or Skip</span></div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── SCOPE CONTROL (P0) ──────────────────────────────────────────────

function ScopeView() {
  const [scopeItems, setScopeItems] = useState([
    { type: "domain", value: "*.target.com", status: "in", note: "Primary wildcard" },
    { type: "domain", value: "target.com", status: "in", note: "Root domain" },
    { type: "ip", value: "203.0.113.0/24", status: "in", note: "Primary IP range" },
    { type: "ip", value: "198.51.100.42", status: "in", note: "Secondary server" },
    { type: "domain", value: "cdn.cloudflare.com", status: "out", note: "Third-party CDN — auto-detected" },
    { type: "domain", value: "analytics.google.com", status: "out", note: "Third-party — auto-detected" },
    { type: "domain", value: "*.dev.target.com", status: "in", note: "Dev environments" },
  ]);
  const [newItem, setNewItem] = useState("");
  const [importSource, setImportSource] = useState(null);

  const inScope = scopeItems.filter(s => s.status === "in");
  const outScope = scopeItems.filter(s => s.status === "out");

  const toggleStatus = (i) => {
    setScopeItems(prev => prev.map((s, j) => j === i ? { ...s, status: s.status === "in" ? "out" : "in" } : s));
  };

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 800, color: C.text, fontFamily: mono }}>Scope Control & Authorization</div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>Define what is in-scope and out-of-scope before scanning. All agents enforce these boundaries.</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={() => setImportSource("hackerone")} style={{ padding: "8px 14px", borderRadius: 8, border: `1px solid ${C.border}`, cursor: "pointer", background: "transparent", color: C.text, fontSize: 11, fontFamily: mono, fontWeight: 600 }}>Import from HackerOne</button>
          <button onClick={() => setImportSource("bugcrowd")} style={{ padding: "8px 14px", borderRadius: 8, border: `1px solid ${C.border}`, cursor: "pointer", background: "transparent", color: C.text, fontSize: 11, fontFamily: mono, fontWeight: 600 }}>Import from Bugcrowd</button>
        </div>
      </div>

      {/* Scope enforcement banner */}
      <div style={{ background: C.greenDim, border: `1px solid ${C.green}33`, borderRadius: 10, padding: 14, marginBottom: 20, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 36, height: 36, borderRadius: "50%", background: `${C.green}22`, border: `2px solid ${C.green}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🔒</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.green, fontFamily: mono }}>SCOPE ENFORCEMENT: ACTIVE</div>
          <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>3-level enforcement: API validates on scan creation → Orchestrator checks before dispatch → Each agent validates every outbound request</div>
        </div>
        <div style={{ textAlign: "center", padding: "4px 14px", borderRadius: 6, background: C.bgCard, border: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 16, fontWeight: 800, color: C.green, fontFamily: mono }}>{inScope.length}</div>
          <div style={{ fontSize: 9, color: C.muted, fontFamily: mono }}>IN-SCOPE</div>
        </div>
        <div style={{ textAlign: "center", padding: "4px 14px", borderRadius: 6, background: C.bgCard, border: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 16, fontWeight: 800, color: C.red, fontFamily: mono }}>{outScope.length}</div>
          <div style={{ fontSize: 9, color: C.muted, fontFamily: mono }}>EXCLUDED</div>
        </div>
      </div>

      {/* Add new scope item */}
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input value={newItem} onChange={e => setNewItem(e.target.value)} placeholder="Add domain, IP, or CIDR (e.g., *.staging.target.com or 10.0.0.0/8)"
          style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: `1px solid ${C.border}`, background: C.bgCard, color: C.text, fontSize: 12, fontFamily: mono, outline: "none", boxSizing: "border-box" }} />
        <button style={{ padding: "10px 18px", borderRadius: 8, border: "none", cursor: "pointer", background: C.green, color: "#fff", fontSize: 11, fontWeight: 700, fontFamily: mono }}>+ Add In-Scope</button>
        <button style={{ padding: "10px 18px", borderRadius: 8, border: "none", cursor: "pointer", background: C.red, color: "#fff", fontSize: 11, fontWeight: 700, fontFamily: mono }}>+ Add Exclusion</button>
      </div>

      {/* In-scope items */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: C.green, fontFamily: mono, marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
          <span>✓ IN-SCOPE TARGETS</span>
          <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 10, background: C.greenDim, fontWeight: 400 }}>{inScope.length}</span>
        </div>
        {inScope.map((s, i) => {
          const idx = scopeItems.indexOf(s);
          return (
            <div key={idx} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderRadius: 8, background: C.bgCard, border: `1px solid ${C.border}`, marginBottom: 6, borderLeft: `3px solid ${C.green}` }}>
              <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, background: s.type === "domain" ? C.cyanDim : C.purpleDim, color: s.type === "domain" ? C.cyan : C.purple, fontFamily: mono, fontWeight: 700, textTransform: "uppercase" }}>{s.type}</span>
              <span style={{ fontSize: 12.5, fontWeight: 700, color: C.text, fontFamily: mono, flex: 1 }}>{s.value}</span>
              <span style={{ fontSize: 10, color: C.dim }}>{s.note}</span>
              <button onClick={() => toggleStatus(idx)} style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.red}44`, background: C.redDim, color: C.red, fontSize: 10, fontFamily: mono, cursor: "pointer", fontWeight: 600 }}>Exclude</button>
            </div>
          );
        })}
      </div>

      {/* Out-of-scope items */}
      <div>
        <div style={{ fontSize: 13, fontWeight: 700, color: C.red, fontFamily: mono, marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
          <span>✕ OUT-OF-SCOPE (BLOCKED)</span>
          <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 10, background: C.redDim, fontWeight: 400 }}>{outScope.length}</span>
        </div>
        {outScope.map((s, i) => {
          const idx = scopeItems.indexOf(s);
          return (
            <div key={idx} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderRadius: 8, background: C.bgCard, border: `1px solid ${C.border}`, marginBottom: 6, borderLeft: `3px solid ${C.red}`, opacity: 0.7 }}>
              <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, background: s.type === "domain" ? C.cyanDim : C.purpleDim, color: s.type === "domain" ? C.cyan : C.purple, fontFamily: mono, fontWeight: 700, textTransform: "uppercase" }}>{s.type}</span>
              <span style={{ fontSize: 12.5, fontWeight: 600, color: C.muted, fontFamily: mono, flex: 1, textDecoration: "line-through" }}>{s.value}</span>
              <span style={{ fontSize: 10, color: C.dim }}>{s.note}</span>
              <button onClick={() => toggleStatus(idx)} style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.green}44`, background: C.greenDim, color: C.green, fontSize: 10, fontFamily: mono, cursor: "pointer", fontWeight: 600 }}>Move In-Scope</button>
            </div>
          );
        })}
      </div>

      {/* Blocked requests log */}
      <div style={{ marginTop: 20, background: C.bgCard, borderRadius: 10, padding: 16, border: `1px solid ${C.border}` }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: mono, marginBottom: 10 }}>SCOPE VIOLATION LOG (last 5)</div>
        {[
          { time: "14:28:33", agent: "Subdomain Agent", target: "cdn.cloudflare.com", reason: "Third-party domain in exclusion list" },
          { time: "14:29:01", agent: "Web Recon Agent", target: "analytics.google.com", reason: "Third-party domain in exclusion list" },
          { time: "14:31:15", agent: "Dir/File Discovery", target: "cdn.cloudflare.com/admin", reason: "Parent domain excluded" },
        ].map((v, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 10px", borderRadius: 4, background: C.bgSurface, marginBottom: 4, borderLeft: `2px solid ${C.red}` }}>
            <span style={{ fontSize: 10, color: C.dim, fontFamily: mono, minWidth: 65 }}>{v.time}</span>
            <span style={{ fontSize: 10, color: C.orange, fontFamily: mono, minWidth: 130 }}>{v.agent}</span>
            <span style={{ fontSize: 10.5, color: C.text, fontFamily: mono, flex: 1 }}>{v.target}</span>
            <span style={{ fontSize: 10, color: C.red, fontFamily: mono }}>BLOCKED: {v.reason}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── REPORT GENERATION (P0) ──────────────────────────────────────────

function ReportsView() {
  const [selectedTemplate, setSelectedTemplate] = useState("full");
  const [generating, setGenerating] = useState(false);
  const [sections, setSections] = useState({
    executive_summary: true, scope: true, methodology: true, mitre_heatmap: true,
    critical_findings: true, all_findings: true, credential_leaks: true,
    threat_intel: true, attack_chains: true, remediation: true, appendix: true,
  });

  const templates = [
    { id: "full", name: "Full Pentest Report", desc: "Complete report with all sections, MITRE mapping, and attack chains", pages: "~25-40 pages" },
    { id: "executive", name: "Executive Summary", desc: "High-level overview for C-suite and board presentation", pages: "~3-5 pages" },
    { id: "vulnerability", name: "Vulnerability Report", desc: "Focused on discovered vulnerabilities with remediation steps", pages: "~10-20 pages" },
    { id: "credential", name: "Credential Exposure Report", desc: "Leaked credentials analysis with password reuse patterns", pages: "~5-10 pages" },
    { id: "compliance", name: "Compliance Report", desc: "Mapped to NIST CSF / ISO 27001 control requirements", pages: "~15-25 pages" },
  ];

  const pastReports = [
    { date: "2026-03-12", template: "Full Pentest Report", target: "target.com", format: "PDF", size: "2.4 MB" },
    { date: "2026-03-10", template: "Executive Summary", target: "target.com", format: "DOCX", size: "890 KB" },
    { date: "2026-03-05", template: "Vulnerability Report", target: "staging.target.com", format: "PDF", size: "1.8 MB" },
  ];

  return (
    <div style={{ padding: 24 }}>
      <div style={{ fontSize: 18, fontWeight: 800, color: C.text, marginBottom: 4, fontFamily: mono }}>Report Generation</div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>AI-powered reports with MITRE ATT&CK mapping, attack chain narratives, and remediation guidance</div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
        {/* Left: Template Selection */}
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, fontFamily: mono, marginBottom: 12 }}>SELECT TEMPLATE</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {templates.map(t => (
              <div key={t.id} onClick={() => setSelectedTemplate(t.id)} style={{
                padding: "14px 16px", borderRadius: 10, cursor: "pointer",
                background: selectedTemplate === t.id ? C.accentGlow : C.bgCard,
                border: `1px solid ${selectedTemplate === t.id ? C.accent : C.border}`,
                transition: "all 0.2s",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span style={{ fontSize: 12.5, fontWeight: 700, color: C.text, fontFamily: mono }}>{t.name}</span>
                  <span style={{ fontSize: 10, color: C.dim, fontFamily: mono }}>{t.pages}</span>
                </div>
                <div style={{ fontSize: 11, color: C.muted }}>{t.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Customization */}
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, fontFamily: mono, marginBottom: 12 }}>CUSTOMIZE REPORT</div>

          {/* Branding */}
          <div style={{ background: C.bgCard, borderRadius: 10, padding: 16, border: `1px solid ${C.border}`, marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.muted, fontFamily: mono, marginBottom: 10, letterSpacing: "0.5px" }}>BRANDING</div>
            {[["Company Name", "Target Security Consulting"], ["Report Title Override", ""], ["Primary Color", "#3B82F6"]].map(([label, val], i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                <span style={{ fontSize: 11, color: C.muted, fontFamily: mono, minWidth: 140 }}>{label}</span>
                <input defaultValue={val} placeholder={`Enter ${label.toLowerCase()}...`} style={{ flex: 1, padding: "6px 10px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.bgSurface, color: C.text, fontSize: 11, fontFamily: mono, outline: "none", boxSizing: "border-box" }} />
              </div>
            ))}
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: 11, color: C.muted, fontFamily: mono, minWidth: 140 }}>Company Logo</span>
              <button style={{ padding: "6px 14px", borderRadius: 6, border: `1px dashed ${C.border}`, background: "transparent", color: C.muted, fontSize: 11, fontFamily: mono, cursor: "pointer" }}>📎 Upload Logo</button>
            </div>
          </div>

          {/* Sections */}
          <div style={{ background: C.bgCard, borderRadius: 10, padding: 16, border: `1px solid ${C.border}`, marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.muted, fontFamily: mono, marginBottom: 10, letterSpacing: "0.5px" }}>INCLUDE SECTIONS</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {Object.entries(sections).map(([k, v]) => (
                <div key={k} onClick={() => setSections(prev => ({ ...prev, [k]: !prev[k] }))} style={{
                  padding: "5px 10px", borderRadius: 6, cursor: "pointer",
                  background: v ? C.accentGlow : C.bgSurface,
                  border: `1px solid ${v ? C.accent + "44" : C.border}`,
                  display: "flex", alignItems: "center", gap: 6,
                }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: v ? C.accent : C.dim }} />
                  <span style={{ fontSize: 10, color: v ? C.text : C.muted, fontFamily: mono }}>{k.replace(/_/g, " ")}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Export format */}
          <div style={{ background: C.bgCard, borderRadius: 10, padding: 16, border: `1px solid ${C.border}`, marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.muted, fontFamily: mono, marginBottom: 10, letterSpacing: "0.5px" }}>EXPORT FORMAT</div>
            <div style={{ display: "flex", gap: 8 }}>
              {["PDF", "DOCX", "JSON", "HTML"].map(f => (
                <button key={f} style={{ padding: "8px 20px", borderRadius: 6, border: `1px solid ${f === "PDF" ? C.accent : C.border}`, cursor: "pointer", background: f === "PDF" ? C.accentGlow : "transparent", color: f === "PDF" ? C.accent : C.muted, fontSize: 11, fontFamily: mono, fontWeight: 700 }}>{f}</button>
              ))}
            </div>
          </div>

          {/* Generate button */}
          <button onClick={() => setGenerating(true)} style={{
            width: "100%", padding: "14px", borderRadius: 10, border: "none", cursor: "pointer",
            background: generating ? C.yellowDim : `linear-gradient(135deg, ${C.accent}, ${C.cyan})`,
            color: generating ? C.yellow : "#fff", fontSize: 13, fontWeight: 700, fontFamily: mono,
            boxShadow: generating ? "none" : `0 0 20px ${C.accent}30`,
          }}>
            {generating ? "⏳ Generating with Sonnet 4.6... (est. 30s)" : "📄 Generate Report"}
          </button>
        </div>
      </div>

      {/* Past reports */}
      <div style={{ marginTop: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: C.text, fontFamily: mono, marginBottom: 12 }}>PAST REPORTS</div>
        <div style={{ background: C.bgCard, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1.5fr 2fr 2fr 1fr 1fr 100px", padding: "10px 16px", background: C.bgSurface, borderBottom: `1px solid ${C.border}`, fontSize: 9.5, color: C.muted, fontFamily: mono, fontWeight: 700 }}>
            <span>DATE</span><span>TEMPLATE</span><span>TARGET</span><span>FORMAT</span><span>SIZE</span><span></span>
          </div>
          {pastReports.map((r, i) => (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "1.5fr 2fr 2fr 1fr 1fr 100px", padding: "10px 16px", borderBottom: `1px solid ${C.border}22`, alignItems: "center" }}>
              <span style={{ fontSize: 11, color: C.muted, fontFamily: mono }}>{r.date}</span>
              <span style={{ fontSize: 11, color: C.text, fontFamily: mono }}>{r.template}</span>
              <span style={{ fontSize: 11, color: C.text, fontFamily: mono }}>{r.target}</span>
              <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.accentGlow, color: C.accent, fontFamily: mono, fontWeight: 600, display: "inline-block", width: "fit-content" }}>{r.format}</span>
              <span style={{ fontSize: 11, color: C.dim, fontFamily: mono }}>{r.size}</span>
              <button style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.border}`, background: "transparent", color: C.text, fontSize: 10, fontFamily: mono, cursor: "pointer" }}>⬇ Download</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── SCAN HISTORY & DIFF (P0) ────────────────────────────────────────

function HistoryView() {
  const [selectedScan, setSelectedScan] = useState(1);
  const [compareMode, setCompareMode] = useState(false);
  const [compareScan, setCompareScan] = useState(2);

  const scans = [
    { id: 1, date: "2026-03-12 14:20", target: "target.com", profile: "Full Recon", status: "running", duration: "22m (active)", subdomains: 47, ports: 23, vulns: 18, creds: 34, findings: 218 },
    { id: 2, date: "2026-03-10 09:15", target: "target.com", profile: "Full Recon", status: "completed", duration: "38m", subdomains: 43, ports: 21, vulns: 15, creds: 28, findings: 189 },
    { id: 3, date: "2026-03-05 11:30", target: "target.com", profile: "Passive Only", status: "completed", duration: "12m", subdomains: 38, ports: 0, vulns: 0, creds: 22, findings: 97 },
  ];

  const diffs = [
    { type: "new", category: "subdomain", value: "api-v2.target.com", detail: "New subdomain discovered", severity: "medium" },
    { type: "new", category: "subdomain", value: "staging-new.target.com", detail: "New subdomain with login panel", severity: "high" },
    { type: "new", category: "subdomain", value: "k8s-dashboard.target.com", detail: "Kubernetes dashboard exposed", severity: "critical" },
    { type: "new", category: "subdomain", value: "grafana.target.com", detail: "Grafana monitoring exposed", severity: "high" },
    { type: "new", category: "port", value: "target.com:9090", detail: "New Prometheus metrics endpoint", severity: "medium" },
    { type: "new", category: "port", value: "target.com:6379", detail: "Redis exposed to internet!", severity: "critical" },
    { type: "new", category: "credential", value: "devops@target.com", detail: "6 new leaked credentials since last scan", severity: "high" },
    { type: "new", category: "vuln", value: "CVE-2025-1234", detail: "New critical CVE affecting nginx 1.18", severity: "critical" },
    { type: "new", category: "vuln", value: "CVE-2025-0567", detail: "MySQL 5.7 auth bypass", severity: "critical" },
    { type: "new", category: "vuln", value: "XSS in /search", detail: "Reflected XSS in search parameter", severity: "medium" },
    { type: "removed", category: "port", value: "target.com:8080", detail: "Port closed (was HTTP proxy)", severity: "info" },
    { type: "removed", category: "vuln", value: "CVE-2024-3400", detail: "PAN-OS patched — no longer vulnerable", severity: "info" },
  ];

  const s1 = scans.find(s => s.id === selectedScan);
  const s2 = scans.find(s => s.id === compareScan);
  const newItems = diffs.filter(d => d.type === "new");
  const removedItems = diffs.filter(d => d.type === "removed");

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 800, color: C.text, fontFamily: mono }}>Scan History & Comparison</div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>Track changes between scans, monitor attack surface evolution</div>
        </div>
        <button onClick={() => setCompareMode(!compareMode)} style={{
          padding: "8px 16px", borderRadius: 8, border: `1px solid ${compareMode ? C.accent : C.border}`,
          cursor: "pointer", background: compareMode ? C.accentGlow : "transparent",
          color: compareMode ? C.accent : C.muted, fontSize: 11, fontWeight: 700, fontFamily: mono,
        }}>{compareMode ? "✓ Compare Mode ON" : "⇄ Enable Compare Mode"}</button>
      </div>

      {/* Scan list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 20 }}>
        {scans.map(s => (
          <div key={s.id} onClick={() => compareMode ? setCompareScan(s.id) : setSelectedScan(s.id)}
            style={{
              display: "flex", alignItems: "center", gap: 14, padding: "14px 18px", borderRadius: 10,
              background: C.bgCard, cursor: "pointer",
              border: `1px solid ${(selectedScan === s.id || (compareMode && compareScan === s.id)) ? C.accent : C.border}`,
              borderLeft: `4px solid ${s.status === "running" ? C.accent : s.status === "completed" ? C.green : C.dim}`,
            }}>
            <div style={{ minWidth: 140 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: mono }}>{s.date}</div>
              <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{s.profile} • {s.duration}</div>
            </div>
            <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 4, background: s.status === "running" ? C.accentGlow : C.greenDim, color: s.status === "running" ? C.accent : C.green, fontFamily: mono, fontWeight: 600 }}>{s.status}</span>
            <div style={{ flex: 1, display: "flex", gap: 16 }}>
              {[["Subs", s.subdomains, C.cyan], ["Ports", s.ports, C.accent], ["Vulns", s.vulns, C.red], ["Creds", s.creds, C.orange]].map(([label, val, col]) => (
                <div key={label} style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 14, fontWeight: 800, color: col, fontFamily: mono }}>{val}</div>
                  <div style={{ fontSize: 9, color: C.dim, fontFamily: mono }}>{label}</div>
                </div>
              ))}
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 16, fontWeight: 800, color: C.text, fontFamily: mono }}>{s.findings}</div>
              <div style={{ fontSize: 9, color: C.dim, fontFamily: mono }}>findings</div>
            </div>
            {selectedScan === s.id && <div style={{ width: 4, height: 30, borderRadius: 2, background: C.accent }} />}
            {compareMode && compareScan === s.id && <div style={{ width: 4, height: 30, borderRadius: 2, background: C.purple }} />}
          </div>
        ))}
      </div>

      {/* Diff view */}
      {compareMode && s1 && s2 && (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: C.accent, fontFamily: mono }}>Scan #{selectedScan} ({s1.date.split(" ")[0]})</span>
            <span style={{ fontSize: 12, color: C.muted }}>vs</span>
            <span style={{ fontSize: 13, fontWeight: 700, color: C.purple, fontFamily: mono }}>Scan #{compareScan} ({s2.date.split(" ")[0]})</span>
          </div>

          {/* Summary stats */}
          <div style={{ display: "flex", gap: 12, marginBottom: 18 }}>
            {[
              ["New Findings", `+${newItems.length}`, C.red],
              ["Resolved", removedItems.length.toString(), C.green],
              ["Subdomains", `${s1.subdomains - s2.subdomains >= 0 ? "+" : ""}${s1.subdomains - s2.subdomains}`, C.cyan],
              ["Ports", `${s1.ports - s2.ports >= 0 ? "+" : ""}${s1.ports - s2.ports}`, C.accent],
              ["Creds", `${s1.creds - s2.creds >= 0 ? "+" : ""}${s1.creds - s2.creds}`, C.orange],
            ].map(([label, val, col]) => (
              <div key={label} style={{ background: C.bgCard, borderRadius: 8, padding: "10px 16px", border: `1px solid ${C.border}`, flex: 1, textAlign: "center" }}>
                <div style={{ fontSize: 18, fontWeight: 800, color: col, fontFamily: mono }}>{val}</div>
                <div style={{ fontSize: 9, color: C.muted, fontFamily: mono, marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </div>

          {/* New items */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.red, fontFamily: mono, marginBottom: 8 }}>🔴 NEW SINCE LAST SCAN ({newItems.length})</div>
            {newItems.map((d, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderRadius: 6, background: C.bgCard, marginBottom: 4, borderLeft: `3px solid ${sevColor(d.severity)}` }}>
                <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.redDim, color: C.red, fontFamily: mono, fontWeight: 700, minWidth: 30, textAlign: "center" }}>+NEW</span>
                <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.bgSurface, color: C.muted, fontFamily: mono, minWidth: 70 }}>{d.category}</span>
                <span style={{ fontSize: 11.5, fontWeight: 700, color: C.text, fontFamily: mono, flex: 1 }}>{d.value}</span>
                <span style={{ fontSize: 10.5, color: C.muted }}>{d.detail}</span>
                <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: sevBg(d.severity), color: sevColor(d.severity), fontFamily: mono, fontWeight: 700, textTransform: "uppercase" }}>{d.severity}</span>
              </div>
            ))}
          </div>

          {/* Removed items */}
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.green, fontFamily: mono, marginBottom: 8 }}>🟢 RESOLVED / REMOVED ({removedItems.length})</div>
            {removedItems.map((d, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderRadius: 6, background: C.bgCard, marginBottom: 4, borderLeft: `3px solid ${C.green}`, opacity: 0.7 }}>
                <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.greenDim, color: C.green, fontFamily: mono, fontWeight: 700, minWidth: 30, textAlign: "center" }}>-FIX</span>
                <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.bgSurface, color: C.muted, fontFamily: mono, minWidth: 70 }}>{d.category}</span>
                <span style={{ fontSize: 11.5, fontWeight: 600, color: C.muted, fontFamily: mono, flex: 1, textDecoration: "line-through" }}>{d.value}</span>
                <span style={{ fontSize: 10.5, color: C.muted }}>{d.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── AI COPILOT CHAT ─────────────────────────────────────────────────

function ChatView() {
  const [messages, setMessages] = useState([
    { role: "system", text: "Recon Sentinel AI Copilot active. I have full context of the current scan against target.com. Ask me anything about findings, suggest next steps, or request specific analysis.", time: "14:20:00" },
    { role: "user", text: "The dir brute force found /backup.sql.gz — is this likely a real database dump or a honeypot?", time: "14:34:12" },
    { role: "ai", text: "Good instinct to question it. Based on the scan data:\n\n• File size is 342KB — consistent with a compressed MySQL dump for a small-medium app\n• The target runs WordPress 6.x with MySQL 5.7 (discovered by Port Agent on 3306)\n• The /wp-admin/ panel is exposed, suggesting weak security hygiene\n• No WAF rules blocked the download request (unlike other endpoints)\n\n**Assessment: Likely real, not a honeypot.** Honeypots typically serve dynamic content with tracking tokens. This is a static .gz file served directly by nginx.\n\n**Recommended next steps:**\n1. Download and inspect the dump headers (don't decompress on target network)\n2. Check if it contains credentials that match the leaked ones from DeHashed\n3. Map to MITRE T1078 (Valid Accounts) if credentials are found\n\nWant me to cross-reference the file discovery with the credential leak data?", time: "14:34:15" },
    { role: "user", text: "Yes, cross-reference credentials. Also, what's the risk rating for the exposed MySQL on port 3306?", time: "14:35:01" },
    { role: "ai", text: "**Credential Cross-Reference:**\nThe Credential Leak Agent found 12 entries for admin@target.com across 5 breaches. 3 have plaintext passwords. If the backup.sql.gz contains the same MySQL user table, we can validate whether:\n- Leaked passwords are still in use\n- Password reuse exists between web app and database\n- Any of the 34 discovered email addresses have admin-level DB access\n\nI'll flag this for the report as a **credential chain**: leaked creds → exposed DB → potential full compromise.\n\n**MySQL 3306 Risk Assessment:**\n🔴 **CRITICAL** — MySQL 5.7 is directly exposed to the internet. This is:\n- MITRE T1190 (Exploit Public-Facing Application)\n- CVE-2023-21912 and CVE-2023-21977 apply to MySQL 5.7\n- Combined with leaked credentials → likely RCE path\n\nThis should be the #1 priority in the report. The attack chain is:\n`Leaked creds (T1078) → Exposed MySQL (T1190) → Database access → Full compromise`\n\nShall I generate a priority remediation section for this?", time: "14:35:04" },
  ]);
  const [input, setInput] = useState("");
  const chatEnd = useRef(null);

  const quickActions = [
    "Summarize all critical findings",
    "Generate attack chain for this target",
    "What should I scan next?",
    "Cross-reference cred leaks with open services",
    "Explain the MITRE mapping for current findings",
    "Draft executive summary for report",
  ];

  const sendMessage = () => {
    if (!input.trim()) return;
    setMessages(prev => [...prev, { role: "user", text: input, time: new Date().toLocaleTimeString("en-US", { hour12: false }) }]);
    setInput("");
    setTimeout(() => {
      setMessages(prev => [...prev, { role: "ai", text: "Analyzing your request against current scan data... (This is a UI mockup — in production, this would stream from Sonnet 4.6 with full scan context via WebSocket)", time: new Date().toLocaleTimeString("en-US", { hour12: false }) }]);
    }, 800);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 58px)" }}>
      {/* Chat header */}
      <div style={{ padding: "12px 20px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 10, background: C.bgSurface }}>
        <div style={{ width: 28, height: 28, borderRadius: "50%", background: `linear-gradient(135deg, ${C.accent}, ${C.cyan})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, color: "#fff", fontWeight: 800 }}>AI</div>
        <div>
          <div style={{ fontSize: 12.5, fontWeight: 700, color: C.text, fontFamily: mono }}>Recon Copilot</div>
          <div style={{ fontSize: 10, color: C.green, fontFamily: mono }}>● Connected — Full scan context loaded (47 subdomains, 218 findings)</div>
        </div>
        <div style={{ marginLeft: "auto", fontSize: 10, padding: "4px 10px", borderRadius: 6, background: C.purpleDim, color: C.purple, fontFamily: mono }}>Model: Sonnet 4.6</div>
      </div>

      {/* Messages area */}
      <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
        {messages.map((m, i) => (
          <div key={i} style={{ display: "flex", gap: 10, marginBottom: 14, flexDirection: m.role === "user" ? "row-reverse" : "row" }}>
            {m.role !== "user" && (
              <div style={{ width: 28, height: 28, borderRadius: "50%", flexShrink: 0, background: m.role === "ai" ? `linear-gradient(135deg, ${C.accent}, ${C.cyan})` : C.purpleDim, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: "#fff", fontWeight: 800, fontFamily: mono }}>{m.role === "ai" ? "AI" : "SYS"}</div>
            )}
            <div style={{
              maxWidth: "75%", padding: "12px 16px", borderRadius: 12,
              background: m.role === "user" ? C.accent : m.role === "system" ? C.purpleDim : C.bgCard,
              border: `1px solid ${m.role === "user" ? C.accent : m.role === "system" ? C.purple + "33" : C.border}`,
              borderTopLeftRadius: m.role === "user" ? 12 : 4,
              borderTopRightRadius: m.role === "user" ? 4 : 12,
            }}>
              <div style={{ fontSize: 12, color: C.text, lineHeight: 1.6, whiteSpace: "pre-wrap", fontFamily: m.role === "ai" ? mono : "inherit" }}>
                {m.text.split("\n").map((line, j) => {
                  if (line.startsWith("**") && line.endsWith("**")) return <div key={j} style={{ fontWeight: 700, color: line.includes("CRITICAL") ? C.red : C.text, marginTop: 4, marginBottom: 2 }}>{line.replace(/\*\*/g, "")}</div>;
                  if (line.startsWith("🔴") || line.startsWith("•") || line.startsWith("-")) return <div key={j} style={{ paddingLeft: 8, color: line.startsWith("🔴") ? C.red : C.muted, marginBottom: 2 }}>{line}</div>;
                  if (line.startsWith("`") && line.endsWith("`")) return <div key={j} style={{ padding: "6px 10px", borderRadius: 4, background: C.bgSurface, fontFamily: mono, fontSize: 11, color: C.cyan, margin: "4px 0" }}>{line.replace(/`/g, "")}</div>;
                  return <div key={j}>{line}</div>;
                })}
              </div>
              <div style={{ fontSize: 9, color: C.dim, marginTop: 6, textAlign: m.role === "user" ? "right" : "left", fontFamily: mono }}>{m.time}</div>
            </div>
          </div>
        ))}
        <div ref={chatEnd} />
      </div>

      {/* Quick actions */}
      <div style={{ padding: "8px 20px", borderTop: `1px solid ${C.border}`, display: "flex", gap: 6, flexWrap: "wrap", background: C.bgSurface }}>
        {quickActions.map((q, i) => (
          <button key={i} onClick={() => { setInput(q); }} style={{
            padding: "5px 10px", borderRadius: 14, border: `1px solid ${C.border}`, cursor: "pointer",
            background: "transparent", color: C.muted, fontSize: 10, fontFamily: mono,
          }}>{q}</button>
        ))}
      </div>

      {/* Input */}
      <div style={{ padding: "12px 20px", borderTop: `1px solid ${C.border}`, display: "flex", gap: 10, background: C.bgSurface }}>
        <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && sendMessage()}
          placeholder="Ask about findings, request analysis, or get recommendations..."
          style={{ flex: 1, padding: "10px 14px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.bgCard, color: C.text, fontSize: 12.5, fontFamily: mono, outline: "none", boxSizing: "border-box" }} />
        <button onClick={sendMessage} style={{ padding: "10px 20px", borderRadius: 10, border: "none", cursor: "pointer", background: `linear-gradient(135deg, ${C.accent}, ${C.cyan})`, color: "#fff", fontSize: 12, fontWeight: 700, fontFamily: mono }}>Send</button>
      </div>
    </div>
  );
}

// ─── NOTIFICATIONS SETTINGS ──────────────────────────────────────────

function NotificationsView() {
  const [channels, setChannels] = useState({
    discord: { enabled: true, webhook: "https://discord.com/api/webhooks/1234567890/abcXYZ...", events: ["critical_finding", "approval_needed", "scan_complete", "agent_error"] },
    slack: { enabled: false, webhook: "", events: ["critical_finding", "scan_complete"] },
    telegram: { enabled: false, botToken: "", chatId: "", events: ["approval_needed"] },
    email: { enabled: true, address: "cyrus@target-security.com", events: ["scan_complete", "daily_report"] },
    webhook: { enabled: false, url: "", events: [] },
  });

  const allEvents = [
    { id: "critical_finding", label: "Critical Finding Discovered", desc: "Immediate alert when a critical-severity finding is detected", color: C.red },
    { id: "approval_needed", label: "Human Approval Needed", desc: "Agent requires user decision to proceed (approval gates + escalations)", color: C.orange },
    { id: "agent_error", label: "Agent Error / Self-Correction Failed", desc: "When an agent cannot auto-resolve and needs manual intervention", color: C.yellow },
    { id: "scan_complete", label: "Scan Complete", desc: "Full scan pipeline has finished all phases", color: C.green },
    { id: "new_subdomain", label: "New Subdomain Discovered", desc: "During continuous monitoring, a new subdomain appears", color: C.cyan },
    { id: "credential_leak", label: "New Credential Leak", desc: "New leaked credential found for target domain", color: C.orange },
    { id: "daily_report", label: "Daily Summary Report", desc: "Automated daily digest of scan status and findings", color: C.purple },
  ];

  const toggleChannel = (ch) => setChannels(prev => ({ ...prev, [ch]: { ...prev[ch], enabled: !prev[ch].enabled } }));
  const toggleEvent = (ch, evtId) => {
    setChannels(prev => {
      const c = { ...prev[ch] };
      c.events = c.events.includes(evtId) ? c.events.filter(e => e !== evtId) : [...c.events, evtId];
      return { ...prev, [ch]: c };
    });
  };

  const channelMeta = {
    discord: { icon: "💬", name: "Discord", fieldLabel: "Webhook URL", field: "webhook" },
    slack: { icon: "📡", name: "Slack", fieldLabel: "Webhook URL", field: "webhook" },
    telegram: { icon: "✈️", name: "Telegram", fieldLabel: "Bot Token", field: "botToken" },
    email: { icon: "📧", name: "Email", fieldLabel: "Email Address", field: "address" },
    webhook: { icon: "🔗", name: "Custom Webhook", fieldLabel: "Endpoint URL", field: "url" },
  };

  return (
    <div style={{ padding: 24 }}>
      <div style={{ fontSize: 18, fontWeight: 800, color: C.text, marginBottom: 4, fontFamily: mono }}>Notification Channels</div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>Get alerted when human action is needed, critical findings emerge, or scans complete</div>

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {Object.entries(channelMeta).map(([key, meta]) => {
          const ch = channels[key];
          return (
            <div key={key} style={{ background: C.bgCard, borderRadius: 10, border: `1px solid ${ch.enabled ? C.accent + "44" : C.border}`, overflow: "hidden" }}>
              {/* Channel header */}
              <div style={{ padding: "14px 18px", display: "flex", alignItems: "center", gap: 12, borderBottom: ch.enabled ? `1px solid ${C.border}` : "none" }}>
                <span style={{ fontSize: 18 }}>{meta.icon}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: C.text, fontFamily: mono }}>{meta.name}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>{ch.enabled ? `${ch.events.length} events configured` : "Disabled"}</div>
                </div>
                <div onClick={() => toggleChannel(key)} style={{
                  width: 44, height: 24, borderRadius: 12, cursor: "pointer", position: "relative",
                  background: ch.enabled ? C.accent : C.dim, transition: "all 0.3s",
                }}>
                  <div style={{
                    width: 20, height: 20, borderRadius: "50%", background: "#fff", position: "absolute", top: 2,
                    left: ch.enabled ? 22 : 2, transition: "all 0.3s", boxShadow: "0 1px 3px rgba(0,0,0,0.3)",
                  }} />
                </div>
              </div>

              {/* Channel config (expanded when enabled) */}
              {ch.enabled && (
                <div style={{ padding: "14px 18px" }}>
                  {/* Connection field */}
                  <div style={{ marginBottom: 14 }}>
                    <label style={{ fontSize: 10, color: C.muted, fontFamily: mono, display: "block", marginBottom: 4, letterSpacing: "0.5px" }}>{meta.fieldLabel}</label>
                    <input value={ch[meta.field] || ""} readOnly style={{
                      width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${C.border}`,
                      background: C.bgSurface, color: C.text, fontSize: 11, fontFamily: mono, outline: "none", boxSizing: "border-box",
                    }} />
                  </div>

                  {/* Event toggles */}
                  <div style={{ fontSize: 10, color: C.muted, fontFamily: mono, marginBottom: 8, letterSpacing: "0.5px" }}>NOTIFY ON:</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {allEvents.map(evt => {
                      const active = ch.events.includes(evt.id);
                      return (
                        <div key={evt.id} onClick={() => toggleEvent(key, evt.id)} style={{
                          padding: "6px 12px", borderRadius: 6, cursor: "pointer",
                          background: active ? evt.color + "22" : C.bgSurface,
                          border: `1px solid ${active ? evt.color + "44" : C.border}`,
                          display: "flex", alignItems: "center", gap: 6,
                        }}>
                          <div style={{ width: 8, height: 8, borderRadius: 2, background: active ? evt.color : C.dim }} />
                          <span style={{ fontSize: 10.5, color: active ? C.text : C.muted, fontFamily: mono }}>{evt.label}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Test notification */}
      <div style={{ marginTop: 18, display: "flex", gap: 10 }}>
        <button style={{ padding: "10px 18px", borderRadius: 8, border: "none", cursor: "pointer", background: C.accent, color: "#fff", fontSize: 12, fontWeight: 700, fontFamily: mono }}>🔔 Send Test Notification</button>
        <button style={{ padding: "10px 18px", borderRadius: 8, border: `1px solid ${C.border}`, cursor: "pointer", background: "transparent", color: C.text, fontSize: 12, fontWeight: 700, fontFamily: mono }}>Save Configuration</button>
      </div>
    </div>
  );
}

// ─── SETTINGS / CONFIG ───────────────────────────────────────────────

function SettingsView() {
  const [activeTab, setActiveTab] = useState("general");

  const tabs = [
    { id: "general", label: "General" },
    { id: "api_keys", label: "API Keys" },
    { id: "scan_engines", label: "Scan Engines" },
    { id: "agent_config", label: "Agent Config" },
    { id: "llm", label: "LLM / AI" },
  ];

  const apiKeys = [
    { name: "Shodan", key: "aSdF...7890", status: "valid", lastUsed: "2 min ago" },
    { name: "DeHashed", key: "bQwE...1234", status: "valid", lastUsed: "8 min ago" },
    { name: "LeakCheck", key: "cRtY...5678", status: "valid", lastUsed: "8 min ago" },
    { name: "HIBP", key: "dUiO...9012", status: "valid", lastUsed: "12 min ago" },
    { name: "VirusTotal", key: "eFgH...3456", status: "valid", lastUsed: "5 min ago" },
    { name: "SecurityTrails", key: "", status: "missing", lastUsed: "never" },
    { name: "GreyNoise", key: "gJkL...7890", status: "expired", lastUsed: "3 days ago" },
    { name: "Hunter.io", key: "", status: "missing", lastUsed: "never" },
    { name: "Censys", key: "", status: "missing", lastUsed: "never" },
  ];

  return (
    <div style={{ padding: 24 }}>
      <div style={{ fontSize: 18, fontWeight: 800, color: C.text, marginBottom: 4, fontFamily: mono }}>Settings & Configuration</div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>API keys, scan engines, agent behavior, and LLM configuration</div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20, borderBottom: `1px solid ${C.border}`, paddingBottom: 4 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
            padding: "8px 16px", borderRadius: "6px 6px 0 0", border: "none", cursor: "pointer",
            background: activeTab === t.id ? C.accentGlow : "transparent",
            color: activeTab === t.id ? C.text : C.muted,
            fontSize: 12, fontWeight: activeTab === t.id ? 700 : 400, fontFamily: mono,
            borderBottom: activeTab === t.id ? `2px solid ${C.accent}` : "2px solid transparent",
          }}>{t.label}</button>
        ))}
      </div>

      {/* General Settings */}
      {activeTab === "general" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {[
            { label: "Default Scan Profile", type: "select", options: ["Full Recon", "Passive Only", "Quick Assessment", "Red Team Stealth", "Bug Bounty"], value: "Full Recon" },
            { label: "Max Concurrent Agents", type: "select", options: ["3", "5", "8", "10", "15"], value: "8" },
            { label: "Request Rate Limit (req/sec)", type: "input", value: "50", placeholder: "Requests per second" },
            { label: "Request Timeout (seconds)", type: "input", value: "10", placeholder: "Timeout in seconds" },
            { label: "Stealth Level", type: "select", options: ["1 — Fast (noisy)", "2 — Normal", "3 — Careful", "4 — Slow & Low", "5 — Maximum Stealth"], value: "2 — Normal" },
            { label: "Auto-Correction Mode", type: "select", options: ["Full Auto (agent fixes & continues)", "Ask Before Retrying", "Notify Only (no auto-fix)"], value: "Full Auto (agent fixes & continues)" },
            { label: "Default Wordlist (Dir Brute)", type: "select", options: ["SecLists/common.txt", "SecLists/big.txt", "SecLists/raft-medium.txt", "Custom upload..."], value: "SecLists/raft-medium.txt" },
            { label: "Enable Recursive Dir Scanning", type: "toggle", value: true },
            { label: "Save Screenshots", type: "toggle", value: true },
            { label: "Enable Wayback/Historical Recon", type: "toggle", value: true },
          ].map((s, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 16, padding: "10px 14px", borderRadius: 8, background: C.bgCard, border: `1px solid ${C.border}` }}>
              <span style={{ fontSize: 12, color: C.text, fontFamily: mono, flex: 1, minWidth: 220 }}>{s.label}</span>
              {s.type === "select" && (
                <select defaultValue={s.value} style={{ padding: "6px 10px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.bgSurface, color: C.text, fontSize: 11, fontFamily: mono, outline: "none", minWidth: 240 }}>
                  {s.options.map(o => <option key={o}>{o}</option>)}
                </select>
              )}
              {s.type === "input" && (
                <input defaultValue={s.value} placeholder={s.placeholder} style={{ padding: "6px 10px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.bgSurface, color: C.text, fontSize: 11, fontFamily: mono, outline: "none", width: 240, boxSizing: "border-box" }} />
              )}
              {s.type === "toggle" && (
                <div style={{ width: 44, height: 24, borderRadius: 12, cursor: "pointer", position: "relative", background: s.value ? C.accent : C.dim }}>
                  <div style={{ width: 20, height: 20, borderRadius: "50%", background: "#fff", position: "absolute", top: 2, left: s.value ? 22 : 2, boxShadow: "0 1px 3px rgba(0,0,0,0.3)" }} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* API Keys */}
      {activeTab === "api_keys" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {apiKeys.map((k, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 14, padding: "12px 16px", borderRadius: 8, background: C.bgCard, border: `1px solid ${C.border}` }}>
              <span style={{ fontSize: 12.5, fontWeight: 700, color: C.text, fontFamily: mono, minWidth: 140 }}>{k.name}</span>
              <div style={{ flex: 1 }}>
                <input defaultValue={k.key} placeholder="Enter API key..." type="password" style={{
                  width: "100%", padding: "6px 10px", borderRadius: 6, border: `1px solid ${C.border}`,
                  background: C.bgSurface, color: C.text, fontSize: 11, fontFamily: mono, outline: "none", boxSizing: "border-box",
                }} />
              </div>
              <span style={{
                fontSize: 9.5, padding: "3px 8px", borderRadius: 4, fontFamily: mono, fontWeight: 700,
                background: k.status === "valid" ? C.greenDim : k.status === "expired" ? C.orangeDim : C.redDim,
                color: k.status === "valid" ? C.green : k.status === "expired" ? C.orange : C.red,
                textTransform: "uppercase",
              }}>{k.status}</span>
              <span style={{ fontSize: 10, color: C.dim, fontFamily: mono, minWidth: 80, textAlign: "right" }}>{k.lastUsed}</span>
            </div>
          ))}
          <button style={{ padding: "10px 18px", borderRadius: 8, border: `1px dashed ${C.border}`, cursor: "pointer", background: "transparent", color: C.muted, fontSize: 12, fontFamily: mono, marginTop: 4 }}>+ Add Custom API Key</button>
        </div>
      )}

      {/* Scan Engines */}
      {activeTab === "scan_engines" && (
        <div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { name: "Full Recon", desc: "All agents, all phases, maximum coverage", agents: 14, active: true },
              { name: "Passive Only", desc: "OSINT, DNS, certs — no direct target contact", agents: 6, active: true },
              { name: "Quick Assessment", desc: "Top ports, common dirs, known vulns only", agents: 8, active: true },
              { name: "Red Team Stealth", desc: "Slow rate, proxy rotation, randomized timing", agents: 12, active: true },
              { name: "Bug Bounty", desc: "Focus on subdomains, endpoints, common vulns", agents: 10, active: true },
            ].map((e, i) => (
              <div key={i} style={{ padding: "14px 16px", borderRadius: 8, background: C.bgCard, border: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 14 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: C.text, fontFamily: mono }}>{e.name}</div>
                  <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{e.desc}</div>
                </div>
                <span style={{ fontSize: 10, color: C.dim, fontFamily: mono }}>{e.agents} agents</span>
                <button style={{ padding: "6px 14px", borderRadius: 6, border: `1px solid ${C.border}`, cursor: "pointer", background: "transparent", color: C.accent, fontSize: 11, fontFamily: mono, fontWeight: 600 }}>Edit YAML</button>
              </div>
            ))}
            <button style={{ padding: "10px 18px", borderRadius: 8, border: `1px dashed ${C.accent}44`, cursor: "pointer", background: C.accentGlow, color: C.accent, fontSize: 12, fontFamily: mono, fontWeight: 700, marginTop: 4 }}>+ Create New Engine</button>
          </div>
        </div>
      )}

      {/* Agent Config */}
      {activeTab === "agent_config" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {[
            { name: "Dir/File Discovery", setting: "Auto-calibrate on custom 404", value: true, extra: "Wordlist: raft-medium.txt | Extensions: php,asp,aspx,jsp,html" },
            { name: "Port & Service Agent", setting: "Fallback to Connect scan on filter", value: true, extra: "Default: SYN scan | Top 1000 ports | Version intensity: 2" },
            { name: "Subdomain Agent", setting: "Auto-filter DNS wildcards", value: true, extra: "Sources: Subfinder + Amass + crt.sh | Brute: enabled" },
            { name: "Credential Leak Agent", setting: "API failover on rate-limit", value: true, extra: "Priority: DeHashed → LeakCheck → HIBP | Backoff: 60s" },
            { name: "Vulnerability Agent", setting: "Auto-throttle on WAF detection", value: true, extra: "Templates: all | Severity: medium+ | Rate: auto" },
            { name: "Web Recon Agent", setting: "Headless Chrome for SPA detection", value: true, extra: "Wait: 5s | Screenshot: yes | Tech detect: Wappalyzer" },
          ].map((a, i) => (
            <div key={i} style={{ padding: "14px 16px", borderRadius: 8, background: C.bgCard, border: `1px solid ${C.border}` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
                <span style={{ fontSize: 12.5, fontWeight: 700, color: C.text, fontFamily: mono, flex: 1 }}>{a.name}</span>
                <span style={{ fontSize: 10, color: C.muted, fontFamily: mono }}>{a.setting}</span>
                <div style={{ width: 44, height: 24, borderRadius: 12, cursor: "pointer", position: "relative", background: a.value ? C.green : C.dim }}>
                  <div style={{ width: 20, height: 20, borderRadius: "50%", background: "#fff", position: "absolute", top: 2, left: a.value ? 22 : 2, boxShadow: "0 1px 3px rgba(0,0,0,0.3)" }} />
                </div>
              </div>
              <div style={{ fontSize: 10, color: C.dim, fontFamily: mono, padding: "6px 8px", borderRadius: 4, background: C.bgSurface }}>{a.extra}</div>
            </div>
          ))}
        </div>
      )}

      {/* LLM Config */}
      {activeTab === "llm" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {[
            { label: "Orchestrator (Routing/Planning)", model: "Haiku 4.5", cost: "~$0.015/scan", desc: "Fast, cheap routing decisions. Decides which agents to run and in what order." },
            { label: "Analyzer (Approval Gates)", model: "Sonnet 4.6", cost: "~$0.075/analysis", desc: "Reviews findings at approval gates, generates recommendations for user." },
            { label: "Report Generator", model: "Sonnet 4.6", cost: "~$0.12/report", desc: "Writes executive summaries, remediation guides, MITRE-aligned narrative." },
            { label: "Copilot Chat", model: "Sonnet 4.6", cost: "~$0.03/message", desc: "Interactive chat with full scan context. Answers questions, suggests next steps." },
            { label: "Complex Reasoning (rare)", model: "Opus 4.6", cost: "~$0.075/call", desc: "Attack chain analysis, multi-step exploit path reasoning. Used sparingly." },
          ].map((l, i) => (
            <div key={i} style={{ padding: "14px 16px", borderRadius: 8, background: C.bgCard, border: `1px solid ${C.border}` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
                <span style={{ fontSize: 12.5, fontWeight: 700, color: C.text, fontFamily: mono, flex: 1 }}>{l.label}</span>
                <select defaultValue={l.model} style={{ padding: "5px 10px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.bgSurface, color: C.accent, fontSize: 11, fontFamily: mono, outline: "none", fontWeight: 600 }}>
                  <option>Haiku 4.5</option><option>Sonnet 4.6</option><option>Opus 4.6</option><option>Ollama (local)</option><option>DeepSeek V3</option>
                </select>
                <span style={{ fontSize: 10, color: C.dim, fontFamily: mono, minWidth: 100, textAlign: "right" }}>{l.cost}</span>
              </div>
              <div style={{ fontSize: 10.5, color: C.muted, lineHeight: 1.4 }}>{l.desc}</div>
            </div>
          ))}
          <div style={{ padding: "14px 16px", borderRadius: 8, background: C.purpleDim, border: `1px solid ${C.purple}33` }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.purple, fontFamily: mono, marginBottom: 4 }}>Estimated Monthly LLM Cost</div>
            <div style={{ fontSize: 11, color: C.muted }}>At 10 scans/day with prompt caching: <strong style={{ color: C.text }}>~$30-40/month</strong> (Haiku routing + Sonnet analysis + Sonnet reports)</div>
          </div>
        </div>
      )}

      {/* Save button */}
      <div style={{ marginTop: 20, display: "flex", gap: 10 }}>
        <button style={{ padding: "10px 22px", borderRadius: 8, border: "none", cursor: "pointer", background: C.accent, color: "#fff", fontSize: 12, fontWeight: 700, fontFamily: mono }}>💾 Save All Settings</button>
        <button style={{ padding: "10px 22px", borderRadius: 8, border: `1px solid ${C.border}`, cursor: "pointer", background: "transparent", color: C.muted, fontSize: 12, fontFamily: mono }}>Reset to Defaults</button>
      </div>
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────────

export default function App() {
  const [view, setView] = useState("dashboard");
  const [target, setTarget] = useState("target.com");
  const [inputType, setInputType] = useState("url");
  const [showPalette, setShowPalette] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");

  // P1: Global keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setShowPalette(true); setPaletteQuery(""); }
      if (e.key === "Escape") { setShowPalette(false); }
      if ((e.metaKey || e.ctrlKey) && e.key === "/") { e.preventDefault(); setView("chat"); }
      // Number keys for view switching (when palette not open and not in input)
      if (!showPalette && !["INPUT","TEXTAREA","SELECT"].includes(document.activeElement?.tagName)) {
        const viewKeys = { "1": "dashboard", "2": "agents", "3": "health", "4": "findings", "5": "mitre", "6": "scope", "7": "reports", "8": "history", "9": "chat" };
        if (viewKeys[e.key]) { setView(viewKeys[e.key]); }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [showPalette]);

  const paletteItems = [
    { label: "Go to Dashboard", action: () => setView("dashboard"), icon: "◆", shortcut: "1" },
    { label: "Go to Agent Orchestration", action: () => setView("agents"), icon: "⬡", shortcut: "2" },
    { label: "Go to Agent Health Feed", action: () => setView("health"), icon: "♡", shortcut: "3" },
    { label: "Go to Findings", action: () => setView("findings"), icon: "◈", shortcut: "4" },
    { label: "Go to MITRE ATT&CK", action: () => setView("mitre"), icon: "◉", shortcut: "5" },
    { label: "Go to Scope Control", action: () => setView("scope"), icon: "⊘", shortcut: "6" },
    { label: "Go to Reports", action: () => setView("reports"), icon: "⊞", shortcut: "7" },
    { label: "Go to Scan History", action: () => setView("history"), icon: "⊡", shortcut: "8" },
    { label: "Open AI Copilot Chat", action: () => setView("chat"), icon: "⊹", shortcut: "Ctrl+/" },
    { label: "Go to Settings", action: () => setView("settings"), icon: "⊙" },
    { label: "Search findings: critical", action: () => setView("findings"), icon: "🔍" },
    { label: "Search findings: T1078 Valid Accounts", action: () => setView("mitre"), icon: "🔍" },
    { label: "Search findings: leaked credentials", action: () => setView("credentials"), icon: "🔍" },
    { label: "Generate Report", action: () => setView("reports"), icon: "📄" },
    { label: "Compare Scans", action: () => setView("history"), icon: "⇄" },
    { label: "View Scope Violations", action: () => setView("scope"), icon: "⊘" },
  ];

  const filteredPalette = paletteQuery
    ? paletteItems.filter(i => i.label.toLowerCase().includes(paletteQuery.toLowerCase()))
    : paletteItems;

  const views = {
    dashboard: <DashboardView />,
    agents: <AgentsView />,
    health: <HealthFeedView />,
    findings: <FindingsView />,
    mitre: <MITREView />,
    credentials: <CredentialsView />,
    flow: <FlowView />,
    scope: <ScopeView />,
    reports: <ReportsView />,
    history: <HistoryView />,
    chat: <ChatView />,
    notifications: <NotificationsView />,
    settings: <SettingsView />,
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }}>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
      <Sidebar view={view} setView={setView} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "auto", maxHeight: "100vh" }}>
        <Header target={target} setTarget={setTarget} inputType={inputType} setInputType={setInputType} showPalette={showPalette} setShowPalette={setShowPalette} />
        {views[view] || <DashboardView />}
      </div>

      {/* P1: Command Palette (Ctrl+K) */}
      {showPalette && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)", display: "flex", alignItems: "flex-start", justifyContent: "center", paddingTop: 120, zIndex: 9999 }} onClick={() => setShowPalette(false)}>
          <div onClick={e => e.stopPropagation()} style={{ width: 560, background: C.bgCard, borderRadius: 14, border: `1px solid ${C.accent}44`, boxShadow: `0 20px 60px rgba(0,0,0,0.5), 0 0 40px ${C.accent}15`, overflow: "hidden" }}>
            <div style={{ padding: "14px 18px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: 14, color: C.accent }}>⌘</span>
              <input autoFocus value={paletteQuery} onChange={e => setPaletteQuery(e.target.value)}
                placeholder="Type a command, search findings, navigate..."
                style={{ flex: 1, border: "none", background: "transparent", color: C.text, fontSize: 14, fontFamily: mono, outline: "none" }}
                onKeyDown={e => { if (e.key === "Enter" && filteredPalette.length > 0) { filteredPalette[0].action(); setShowPalette(false); } }}
              />
              <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 4, background: C.bgSurface, color: C.dim, fontFamily: mono }}>ESC</span>
            </div>
            <div style={{ maxHeight: 400, overflow: "auto" }}>
              {filteredPalette.map((item, i) => (
                <div key={i} onClick={() => { item.action(); setShowPalette(false); }} style={{
                  padding: "10px 18px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10,
                  background: i === 0 ? C.accentGlow : "transparent",
                  borderLeft: i === 0 ? `3px solid ${C.accent}` : "3px solid transparent",
                }}>
                  <span style={{ fontSize: 13, width: 20, textAlign: "center" }}>{item.icon}</span>
                  <span style={{ fontSize: 12.5, color: i === 0 ? C.text : C.muted, fontFamily: mono, flex: 1 }}>{item.label}</span>
                  {item.shortcut && <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.bgSurface, color: C.dim, fontFamily: mono }}>{item.shortcut}</span>}
                </div>
              ))}
              {filteredPalette.length === 0 && (
                <div style={{ padding: "20px 18px", textAlign: "center", color: C.dim, fontFamily: mono, fontSize: 12 }}>No matching commands</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
