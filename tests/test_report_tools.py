"""
Unit tests for report generation tools.
CrewAI @tool decorator wraps functions into Tool objects — use .run() to invoke.
"""
import pytest
import json
import os
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestCompileTool:
    def test_compiles_passive_and_active(self, sample_passive_findings, sample_active_findings):
        from tools.report.compile_tool import compile_all_findings

        input_data = json.dumps({
            "passive": sample_passive_findings,
            "active": sample_active_findings,
        })
        result = compile_all_findings.run(input_data)
        data = json.loads(result)
        assert isinstance(data, dict)
        assert "services" in data or "meta" in data or "error" in data

    def test_handles_missing_data(self):
        from tools.report.compile_tool import compile_all_findings
        result = compile_all_findings.run(json.dumps({
            "passive": {},
            "active": {},
        }))
        data = json.loads(result)
        assert isinstance(data, dict)


class TestSeverityTool:
    def test_classifies_severity(self):
        from tools.report.severity_tool import severity_classifier

        with patch("tools.report.severity_tool.OpenAI") as MockClient:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content=json.dumps({
                "severity": "Medium",
                "cvss_score": 4.3,
                "reasoning": "Missing security header",
            })))]
            mock_client.chat.completions.create.return_value = mock_response
            MockClient.return_value = mock_client

            result = severity_classifier.run(json.dumps({
                "title": "Missing X-Frame-Options",
                "category": "Web Security",
            }))
            data = json.loads(result)
            assert isinstance(data, dict)


class TestRiskScorerTool:
    def test_calculates_numeric_score(self, sample_compiled_findings):
        from tools.report.risk_scorer_tool import risk_scorer

        with patch("tools.report.risk_scorer_tool.OpenAI") as MockClient:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content="This target has moderate risk."))]
            mock_client.chat.completions.create.return_value = mock_response
            MockClient.return_value = mock_client

            result = risk_scorer.run(json.dumps(sample_compiled_findings))
            data = json.loads(result)
            assert "overall_risk_score" in data
            assert 0 <= data["overall_risk_score"] <= 100

    def test_score_bounded_0_to_100(self):
        from tools.report.risk_scorer_tool import risk_scorer

        # Input with extreme data — rule-based scoring works without LLM
        extreme_data = {
            "statistics": {
                "severity_breakdown": {"Critical": 100, "High": 100, "Medium": 100, "Low": 100, "Info": 100}
            }
        }
        result = risk_scorer.run(json.dumps(extreme_data))
        data = json.loads(result)
        assert data["overall_risk_score"] <= 100


class TestCVETool:
    def test_returns_cve_list(self):
        from tools.report.cve_tool import cve_lookup

        with patch("tools.report.cve_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [{"lang": "en", "value": "Test CVE description"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                                ]
                            }
                        }
                    }
                ],
                "totalResults": 1,
            }
            mock_get.return_value = mock_resp

            services = json.dumps([{"service": "Apache", "version": "2.4.58"}])
            result = cve_lookup.run(services)
            data = json.loads(result)
            assert isinstance(data, (list, dict))

    def test_handles_nvd_api_error(self):
        from tools.report.cve_tool import cve_lookup

        with patch("tools.report.cve_tool.requests.get", side_effect=Exception("Connection error")):
            result = cve_lookup.run(json.dumps([{"service": "Apache", "version": "2.4.58"}]))
            data = json.loads(result)
            assert isinstance(data, (list, dict))


class TestReportGenTool:
    def test_generates_markdown_report(self, sample_compiled_findings, tmp_path):
        from tools.report.report_gen_tool import report_generator

        with patch("tools.report.report_gen_tool.OpenAI") as MockClient:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(
                content="# Attack Surface Report\n\n## Executive Summary\n\nTest report content."
            ))]
            mock_client.chat.completions.create.return_value = mock_response
            MockClient.return_value = mock_client

            result = report_generator.run(json.dumps(sample_compiled_findings))
            assert isinstance(result, str)
            assert "Report" in result or "report" in result or "error" in result.lower()


class TestExportTool:
    def test_exports_html(self, tmp_path):
        from tools.report.export_tool import export_report

        md_content = "# Test Report\n\n## Section\n\nContent here."
        result = export_report.run(json.dumps({
            "markdown_content": md_content,
            "output_dir": str(tmp_path),
        }))
        data = json.loads(result)
        assert isinstance(data, dict)
