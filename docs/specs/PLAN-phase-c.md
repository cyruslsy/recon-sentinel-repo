# Plan: Phase C — Cross-Phase Intelligence

## Task 1: C2 — WAF proactive rate adjustment
- Files: `orchestrator.py`, `dir_file.py`, `js_analysis.py`
- Changes:
  - **orchestrator.py**: Move WAF agent to run FIRST in active phase (before per-target fan-out)
  - **dir_file.py**: In execute(), query WAF_DETECTION findings before running ffuf. If WAF detected for target, reduce rate_limit and threads.
  - **js_analysis.py**: Before crawling hosts, check WAF status and add delay between requests.
- Depends: none

## Task 2: C1 — gau seeds dir/file wordlists
- Files: `dir_file.py`
- Changes:
  - In wordlist assembly phase, query HISTORICAL findings (from gau/wayback) for the current scan
  - Extract unique paths from URLs and add to wordlist
  - Cap at 500 seeded paths to avoid bloating
- Depends: Task 1 (dir_file already being modified)

## Task 3: C3 — Tech-specific port scanning
- Files: `port_scan.py`, `tech_context.py`
- Changes:
  - **tech_context.py**: Add TECH_PORTS mapping (MongoDB:27017, Redis:6379, Elasticsearch:9200, Docker:2375, etc.)
  - **port_scan.py**: Before naabu, call get_scan_tech_context() to get extra ports from tech detection. Append to naabu port list.
- Depends: none

## Task 4: C4 — Baseline-before-full probing
- Files: `dir_file.py`, `port_scan.py`
- Changes:
  - **dir_file.py**: Run a small baseline probe (10 paths) first. Analyze 404 patterns, detect custom error pages. Use this baseline to filter false positives in full scan.
  - **port_scan.py**: Run quick top-100 first, then if interesting services found, expand to full scan.
- Depends: Task 1

## Task 5: C5 — Vuln agent shared tech_context
- Files: `vuln.py`
- Changes:
  - Call get_scan_tech_context() to get detected technologies
  - Map technologies to specific Nuclei template tags (e.g. WordPress → "wordpress", Django → "django")
  - Add tech-specific templates to nuclei command alongside KEV and auto-detect
- Depends: none
