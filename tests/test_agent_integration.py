"""
Test Suite 9: Agent Integration
Tests a real agent lifecycle with mocked subprocesses.
Verifies: execute() → parse output → create findings → return results.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.mark.asyncio
async def test_subdomain_agent_produces_findings():
    """SubdomainAgent parses subfinder + crt.sh output into findings."""
    # Mock the run_command to return fake subfinder output
    mock_subfinder_output = "sub1.example.com\nsub2.example.com\napi.example.com\n"
    mock_crtsh_output = '[{"common_name": "mail.example.com"}, {"common_name": "*.example.com"}]'

    with patch("app.agents.base.BaseAgent.run_command", new_callable=AsyncMock) as mock_cmd, \
         patch("app.agents.base.BaseAgent._check_scope", new_callable=AsyncMock, return_value=True), \
         patch("app.agents.base.BaseAgent._create_agent_run", new_callable=AsyncMock), \
         patch("app.agents.base.BaseAgent._update_agent_status", new_callable=AsyncMock), \
         patch("app.agents.base.BaseAgent._create_findings", new_callable=AsyncMock) as mock_create, \
         patch("app.agents.base.BaseAgent.report_progress", new_callable=AsyncMock), \
         patch("app.agents.base.BaseAgent._broadcast", new_callable=AsyncMock):

        # Configure run_command responses
        mock_cmd.side_effect = [
            # First call: subfinder
            {"returncode": 0, "stdout": mock_subfinder_output, "stderr": "", "parsed": None},
            # Second call: DNS resolution for sub1
            {"returncode": 0, "stdout": "1.2.3.4\n", "stderr": ""},
            # Third call: DNS for sub2
            {"returncode": 0, "stdout": "1.2.3.5\n", "stderr": ""},
            # Fourth call: DNS for api
            {"returncode": 0, "stdout": "1.2.3.6\n", "stderr": ""},
            # Fifth call: DNS for mail (from crt.sh)
            {"returncode": 0, "stdout": "1.2.3.7\n", "stderr": ""},
            # Wildcard check
            {"returncode": 0, "stdout": "", "stderr": ""},
        ]

        from app.agents.subdomain import SubdomainAgent

        agent = SubdomainAgent(
            scan_id="00000000-0000-0000-0000-000000000001",
            target_value="example.com",
            project_id="00000000-0000-0000-0000-000000000002",
            config={},
        )

        # Mock the crt.sh HTTP call
        with patch("httpx.AsyncClient") as mock_http:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = [
                {"common_name": "mail.example.com"},
                {"common_name": "*.example.com"},
            ]
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_http.return_value = mock_client

            findings = await agent.execute()

        # Verify findings were produced
        assert len(findings) >= 3, f"Expected at least 3 findings, got {len(findings)}"

        # Check finding structure
        for f in findings:
            assert "finding_type" in f
            assert "severity" in f
            assert "value" in f
            assert "fingerprint" in f

        # Check specific subdomains were found
        values = [f["value"] for f in findings]
        assert any("sub1.example.com" in v for v in values)
        assert any("api.example.com" in v for v in values)


@pytest.mark.asyncio
async def test_agent_respects_scope_check():
    """Agent that fails scope check returns empty findings without executing."""
    with patch("app.agents.base.BaseAgent._check_scope", new_callable=AsyncMock, return_value=False), \
         patch("app.agents.base.BaseAgent._create_agent_run", new_callable=AsyncMock), \
         patch("app.agents.base.BaseAgent._update_agent_status", new_callable=AsyncMock), \
         patch("app.agents.base.BaseAgent.report_progress", new_callable=AsyncMock), \
         patch("app.agents.base.BaseAgent._broadcast", new_callable=AsyncMock):

        from app.agents.subdomain import SubdomainAgent

        agent = SubdomainAgent(
            scan_id="00000000-0000-0000-0000-000000000001",
            target_value="out-of-scope.com",
            project_id="00000000-0000-0000-0000-000000000002",
            config={},
        )

        result = await agent.run()
        assert result.get("findings_count", 0) == 0


@pytest.mark.asyncio
async def test_self_correction_detects_custom_404():
    """DirFileAgent detects custom 404 and adjusts ffuf filter."""
    from app.agents.corrections import Custom404Detector

    # Simulate 90 responses with same content-length (custom 404)
    responses = [{"content_length": 4567, "status": 200}] * 90
    responses += [{"content_length": 1234, "status": 200}] * 10

    result = Custom404Detector.detect(responses)
    assert result is not None
    assert result.pattern == "custom_404"
    assert result.corrected_params["filter_size"] == 4567
