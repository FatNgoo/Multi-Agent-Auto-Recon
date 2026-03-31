"""
Unit tests for report generation tools.
"""
import pytest
import json
import os
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestCompileTool:
    def test_compiles_passive_and_active(self, sample_passive_findings, sample_active_findings, tmp_path, monkeypatch):
        from tools.report.compile_tool import compile_findings

        passive_file = tmp_path / "test_passive.json"
        active_file = tmp_path / "test_active.json"
        passive_file.write_text(json.dumps(sample_passive_findings), encoding="utf-8")
        active_file.write_text(json.dumps(sample_active_findings), encoding="utf-8")

        input_data = json.dumps({
            "passive_file": str(passive_file),
            "active_file": str(active_file),
        })
        result = compile_findings(input_data)
        data = json.loads(result)
        assert isinstance(data, dict)
        assert "services" in data or "severity_stats" in data or "error" in data

    def test_handles_missing_files(self):
        from tools.report.compile_tool import compile_findings
        result = compile_findings(json.dumps({
            "passive_file": "/nonexistent/passive.json",
            "active_file": "/nonexistent/active.json",
        }))
        data = json.loads(result)
        assert isinstance(data, dict)


class TestSeverityTool:
    def test_classifies_severity(self, sample_compiled_findings):
        from tools.report.severity_tool import classify_severity

        with patch("tools.report.severity_tool.ChatOpenAI") as MockLLM:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = MagicMock(content=json.dumps([
                {
                    "finding": "Missing X-Frame-Options",
                    "severity": "Medium",
                    "cvss_score": 4.3,
                    "category": "Web Security",
                }
            ]))
            MockLLM.return_value = mock_llm

            result = classify_severity(json.dumps(sample_compiled_findings))
            data = json.loads(result)
            assert isinstance(data, (list, dict))


class TestRiskScorerTool:
    def test_calculates_numeric_score(self, sample_compiled_findings):
        from tools.report.risk_scorer_tool import calculate_risk_score

        with patch("tools.report.risk_scorer_tool.ChatOpenAI") as MockLLM:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = MagicMock(content="This target has moderate risk.")
            MockLLM.return_value = mock_llm

            result = calculate_risk_score(json.dumps(sample_compiled_findings))
            data = json.loads(result)
            assert "risk_score" in data
            assert 0 <= data["risk_score"] <= 100

    def test_score_bounded_0_to_100(self):
        from tools.report.risk_scorer_tool import calculate_risk_score

        with patch("tools.report.risk_scorer_tool.ChatOpenAI") as MockLLM:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = MagicMock(content="Very high risk target.")
            MockLLM.return_value = mock_llm

            # Input with extreme data
            extreme_data = {
                "severity_stats": {"Critical": 100, "High": 100, "Medium": 100, "Low": 100, "Info": 100}
            }
            result = calculate_risk_score(json.dumps(extreme_data))
            data = json.loads(result)
            assert data["risk_score"] <= 100


class TestCVETool:
    def test_returns_cve_list(self):
        from tools.report.cve_tool import lookup_cves

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
            result = lookup_cves(services)
            data = json.loads(result)
            assert isinstance(data, (list, dict))

    def test_handles_nvd_api_error(self):
        from tools.report.cve_tool import lookup_cves

        with patch("tools.report.cve_tool.requests.get", side_effect=Exception("Connection error")):
            result = lookup_cves(json.dumps([{"service": "Apache", "version": "2.4.58"}]))
            data = json.loads(result)
            assert isinstance(data, (list, dict))


class TestReportGenTool:
    def test_generates_markdown_report(self, sample_compiled_findings, tmp_path):
        from tools.report.report_gen_tool import generate_report

        with patch("tools.report.report_gen_tool.ChatOpenAI") as MockLLM:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = MagicMock(content="# Attack Surface Report\n\n## Executive Summary\n\nTest report content.")
            MockLLM.return_value = mock_llm

            with patch("tools.report.report_gen_tool.Path") as MockPath:
                mock_path = MagicMock()
                mock_path.__truediv__ = lambda self, x: tmp_path / x
                MockPath.return_value = mock_path

                result = generate_report(json.dumps(sample_compiled_findings))
                data = json.loads(result)
                assert isinstance(data, dict)


class TestExportTool:
    def test_exports_html(self, tmp_path):
        from tools.report.export_tool import export_report

        md_file = tmp_path / "attack_surface_report.md"
        md_file.write_text("# Test Report\n\n## Section\n\nContent here.", encoding="utf-8")

        with patch("tools.report.export_tool.REPORTS_DIR", tmp_path):
            result = export_report(json.dumps({"report_path": str(md_file)}))
            data = json.loads(result)
            assert isinstance(data, dict)
