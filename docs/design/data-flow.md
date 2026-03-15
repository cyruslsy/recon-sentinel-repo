# Data Flow Diagram

> Every agent's output has a documented consumer. No orphan data.

## Passive Phase (7 Agents)

| Agent | Produces | Consumed By |
|-------|----------|-------------|
| subdomain | Subdomains (FQDNs) | Active phase fan-out targets |
| osint | Emails + hostnames | cred_leak (emails → HIBP), dir_file (hostnames → wordlist) |
| email_sec | SPF/DKIM/DMARC status | Scenario: phishing trigger |
| threat_intel | Shodan: ports + versions + headers | port_scan, vuln, web_recon (3 consumers) |
| cred_leak | Breached credentials | Scenario: credential stuffing trigger |
| github_dork | Leaked secrets, configs, code | Cross-correlator + cloud compromise scenario |
| wayback/gau | Historical URLs + parameters | dir_file (paths → wordlist), js_analysis (old JS URLs) |

## Active Phase (8 Agent Types × N Subdomains)

| Agent | Produces | Consumed By |
|-------|----------|-------------|
| port_scan | Open ports + banners + versions | vuln (service → template), scenario: remote services |
| web_recon | Live URLs + tech stack + headers | dir_file (base URLs), waf (HTTP responses) |
| ssl_tls | Cert chain + ciphers + expiry | Posture scoring: TLS health |
| dir_file | Discovered paths + response previews | Scenario: credential stuffing (admin panels) |
| js_analysis | Secrets in JS + API endpoints | dir_file (endpoints → wordlist). INDEPENDENT — does NOT read web_recon |
| waf | WAF type + confidence | ALL active agents: reduce rate if WAF > 80% |
| web_spider | Crawled URLs + parameters | dir_file, js_analysis |
| cloud | Buckets + exposed storage | Scenario: cloud compromise |

## Vuln Phase (3 Agents)

| Agent | Produces | Consumed By |
|-------|----------|-------------|
| nuclei | CVEs + verified vulnerabilities | Scenario: exploit, posture score |
| subdomain_takeover | Takeover-able subdomains | Scenario: subdomain takeover |
| badsecrets | Known default secrets/keys | Scenario: exploit |

## Cross-Phase Dependencies

| Source | Data | Consumer | How Used |
|--------|------|----------|----------|
| osint | email addresses | cred_leak | Check each email against HIBP |
| osint | hostnames | dir_file | Add to custom wordlist |
| threat_intel | Shodan open ports | port_scan | Pre-seed port list (C3) |
| threat_intel | Shodan service versions | vuln | Select version-specific Nuclei templates (E6) |
| threat_intel | Shodan HTTP headers | web_recon | Compare live vs Shodan (E6) |
| web_recon | tech stack | vuln | Select tech-specific templates (C5) |
| web_recon | live URLs | dir_file | Base URLs for brute-force |
| wayback/gau | historical paths | dir_file | Merge into custom wordlist (C1) |
| wayback/gau | old JS URLs | js_analysis | Check old JS for secrets |
| js_analysis | API endpoints | dir_file | Add extracted paths to wordlist |
| waf | WAF type + confidence | dir_file, vuln | Reduce rate if WAF > 80% (C2) |
| ALL agents | findings + confidence | Cross-correlator | Boost/lower confidence (E2) |
| DONE phase | completed scan | auto_diff | Compare vs previous scan |

> **Design decision:** Dependencies are READ-ONLY. Agents query DB, never call each other directly.
