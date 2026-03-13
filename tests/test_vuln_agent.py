"""
Test Suite 7: Vulnerability Agent
Tests template selection logic, severity mapping, and MITRE tag extraction.
"""

import pytest
from app.agents.vuln import (
    TECH_TEMPLATE_MAP,
    DEFAULT_TEMPLATES,
    SEVERITY_MAP,
    TAG_MITRE_MAP,
)
from app.models.enums import FindingSeverity


class TestTemplateSelection:
    def test_wordpress_maps_to_templates(self):
        """WordPress tech should map to wordpress template paths."""
        assert "wordpress" in TECH_TEMPLATE_MAP
        paths = TECH_TEMPLATE_MAP["wordpress"]
        assert any("wordpress" in p for p in paths)

    def test_default_templates_include_cves(self):
        """Default templates should include CVE and exposure checks."""
        assert any("cves" in t for t in DEFAULT_TEMPLATES)
        assert any("exposures" in t for t in DEFAULT_TEMPLATES)

    def test_all_tech_keys_lowercase(self):
        """All tech map keys should be lowercase for consistent matching."""
        for key in TECH_TEMPLATE_MAP:
            assert key == key.lower(), f"Key '{key}' is not lowercase"


class TestSeverityMapping:
    def test_critical_maps_correctly(self):
        assert SEVERITY_MAP["critical"] == FindingSeverity.CRITICAL

    def test_high_maps_correctly(self):
        assert SEVERITY_MAP["high"] == FindingSeverity.HIGH

    def test_medium_maps_correctly(self):
        assert SEVERITY_MAP["medium"] == FindingSeverity.MEDIUM

    def test_low_maps_correctly(self):
        assert SEVERITY_MAP["low"] == FindingSeverity.LOW

    def test_info_maps_correctly(self):
        assert SEVERITY_MAP["info"] == FindingSeverity.INFO

    def test_unknown_defaults_to_info(self):
        assert SEVERITY_MAP["unknown"] == FindingSeverity.INFO

    def test_all_nuclei_severities_covered(self):
        """Nuclei outputs these severity strings — all should be mapped."""
        nuclei_severities = {"critical", "high", "medium", "low", "info", "unknown"}
        assert nuclei_severities.issubset(SEVERITY_MAP.keys())


class TestMitreTagMapping:
    def test_cve_maps_to_exploit(self):
        assert "T1190" in TAG_MITRE_MAP["cve"]

    def test_rce_maps_to_exploit_and_execution(self):
        tags = TAG_MITRE_MAP["rce"]
        assert "T1190" in tags
        assert "T1059" in tags

    def test_default_login_maps_to_valid_accounts(self):
        assert "T1078" in TAG_MITRE_MAP["default-login"]

    def test_xss_maps_to_drive_by(self):
        assert "T1189" in TAG_MITRE_MAP["xss"]

    def test_all_tag_values_are_lists(self):
        """All MITRE mappings should be lists of technique IDs."""
        for tag, techniques in TAG_MITRE_MAP.items():
            assert isinstance(techniques, list), f"Tag '{tag}' value is not a list"
            for t in techniques:
                assert t.startswith("T"), f"Technique '{t}' doesn't start with T"
