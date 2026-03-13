"""
Recon Sentinel — Agent Package
9 agents implemented (Week 2 + Week 5), 5 remaining for post-MVP
"""

# Week 2 agents
from app.agents.subdomain import SubdomainAgent, run_subdomain_agent  # noqa: F401
from app.agents.port_scan import PortScanAgent, run_port_scan_agent  # noqa: F401
from app.agents.web_recon import WebReconAgent, run_web_recon_agent  # noqa: F401

# Week 5 agents
from app.agents.dir_file import DirFileAgent, run_dir_file_agent  # noqa: F401
from app.agents.cred_leak import CredentialLeakAgent, run_cred_leak_agent  # noqa: F401
from app.agents.threat_intel import ThreatIntelAgent, run_threat_intel_agent  # noqa: F401
from app.agents.email_sec import EmailSecurityAgent, run_email_sec_agent  # noqa: F401
from app.agents.ssl_tls import SSLTLSAgent, run_ssl_tls_agent  # noqa: F401
from app.agents.osint import OSINTAgent, run_osint_agent  # noqa: F401

# Sprint E agent
from app.agents.vuln import VulnAgent, run_vuln_agent  # noqa: F401

# Gap-closing agents
from app.agents.cloud import CloudAssetAgent, run_cloud_agent  # noqa: F401
from app.agents.js_analysis import JSAnalysisAgent, run_js_analysis_agent  # noqa: F401
from app.agents.subdomain_takeover import SubdomainTakeoverAgent, run_subdomain_takeover_agent  # noqa: F401

# Self-correction patterns
from app.agents.corrections import detect_anomalies  # noqa: F401
