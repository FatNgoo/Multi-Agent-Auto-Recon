"""Integration tests for all fixes from REVIEW_AND_UPDATE.md"""
import json
import sys
import os
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dotenv import load_dotenv
load_dotenv()


class TestWhoisRootDomain:
    def test_extracts_root_from_subdomain(self):
        from tools.passive.whois_tool import _extract_root_domain
        assert _extract_root_domain("scanme.nmap.org") == "nmap.org"

    def test_leaves_root_intact(self):
        from tools.passive.whois_tool import _extract_root_domain
        assert _extract_root_domain("nmap.org") == "nmap.org"

    def test_handles_two_part_tld(self):
        from tools.passive.whois_tool import _extract_root_domain
        assert _extract_root_domain("a.b.co.uk") == "b.co.uk"

    def test_deep_subdomain(self):
        from tools.passive.whois_tool import _extract_root_domain
        assert _extract_root_domain("deep.sub.domain.example.com") == "example.com"

    def test_strips_protocol(self):
        from tools.passive.whois_tool import _extract_root_domain
        assert _extract_root_domain("https://www.example.com/path") == "example.com"


class TestCompileToolSourceLabels:
    def _make_data(self):
        active = {
            "target": "scanme.nmap.org",
            "scan_timestamp": "2026-04-01T00:00:00Z",
            "open_ports": {
                "45.33.32.156": {
                    "22": {"state": "open", "protocol": "tcp", "service": "ssh", "version": "OpenSSH 6.6.1"},
                    "80": {"state": "open", "protocol": "tcp", "service": "http", "version": "Apache 2.4.7"},
                }
            },
            "missing_headers": {"scanme.nmap.org": ["Strict-Transport-Security", "Content-Security-Policy"]},
            "ssl_findings": [{"host": "scanme.nmap.org", "issue": "Port 443 not reachable", "cert_expiry_days": 0}],
            "waf_info": {"scanme.nmap.org": {"detected": False}},
            "cloud_assets": {
                "s3_buckets": [
                    "scanme",  # heuristic string
                    {"name": "verified-bucket", "url": "https://verified-bucket.s3.amazonaws.com",
                     "status": "PUBLIC", "http_code": 200, "confidence": "verified"},
                ],
                "azure_blobs": ["scanme"],
                "gcs_buckets": ["scanme-media"],
            },
        }
        passive = {
            "target": "scanme.nmap.org",
            "shodan_data": {"ports": [22, 80, 123, 9929, 31337]},
            "subdomains": [],
        }
        return passive, active

    def _run_compile(self, tmp_path):
        from tools.report.compile_tool import compile_all_findings
        import tools.report.compile_tool as ct

        passive, active = self._make_data()
        p_path = tmp_path / "findings_passive.json"
        a_path = tmp_path / "findings_active.json"
        c_path = tmp_path / "compiled_findings.json"
        p_path.write_text(json.dumps(passive), encoding="utf-8")
        a_path.write_text(json.dumps(active), encoding="utf-8")

        with patch.object(ct, "PASSIVE_PATH", str(p_path)), \
             patch.object(ct, "ACTIVE_PATH", str(a_path)), \
             patch.object(ct, "COMPILED_PATH", str(c_path)):
            compile_all_findings.run("scanme.nmap.org")

        with open(c_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def test_services_labeled_active_confirmed(self, tmp_path):
        result = self._run_compile(tmp_path)
        for svc in result.get("services", []):
            assert svc.get("source") == "active_confirmed", f"Missing source label on service: {svc}"
        assert len(result["services"]) == 2

    def test_shodan_ports_stored_separately(self, tmp_path):
        result = self._run_compile(tmp_path)
        shodan_ports = result["infrastructure"]["shodan_observed_ports"]
        assert shodan_ports == [22, 80, 123, 9929, 31337]

    def test_string_cloud_buckets_are_info_not_critical(self, tmp_path):
        result = self._run_compile(tmp_path)
        infra = result.get("infrastructure_findings", [])
        # string heuristic entries must not be Critical
        for f in infra:
            if f.get("source") == "heuristic_guess":
                assert f["severity"] == "Info", f"Heuristic bucket promoted to {f['severity']}: {f}"

    def test_verified_public_bucket_is_critical(self, tmp_path):
        result = self._run_compile(tmp_path)
        infra = result.get("infrastructure_findings", [])
        critical = [f for f in infra if f.get("severity") == "Critical"]
        assert len(critical) >= 1
        for f in critical:
            assert f.get("source") == "active_verified"

    def test_statistics_count_real_findings(self, tmp_path):
        result = self._run_compile(tmp_path)
        stats = result.get("statistics", {})
        # missing headers (2 High) + ssl (1 Medium) + waf (1 Medium) + services (2 Info) + public bucket (1 Critical)
        assert stats.get("total_findings", 0) > 0, "total_findings should be > 0"
        assert stats.get("severity_breakdown", {}).get("High", 0) >= 2, "Should count 2+ High findings from missing headers"


class TestGatherStatsDashboard:
    def test_stats_not_all_zeros(self, tmp_path):
        """_gather_stats must return non-zero counts for actual findings."""
        from crew.recon_crew import ReconCrew

        # Write sample passive + active JSON to temp path
        passive = {
            "target": "test.example.com",
            "subdomains": [{"subdomain": "www.example.com", "ip": "1.2.3.4"}],
            "shodan_data": {"ports": [80, 443]},
        }
        active = {
            "target": "test.example.com",
            "open_ports": {
                "1.2.3.4": {
                    "80": {"state": "open", "protocol": "tcp", "service": "http", "version": ""},
                    "443": {"state": "open", "protocol": "tcp", "service": "https", "version": ""},
                }
            },
            "missing_headers": {
                "test.example.com": ["Strict-Transport-Security", "Content-Security-Policy",
                                     "X-Frame-Options"]
            },
            "ssl_findings": [],
            "waf_info": {"test.example.com": {"detected": False}},
            "cloud_assets": {"s3_buckets": [], "azure_blobs": [], "gcs_buckets": []},
            "dangerous_methods": {},
        }
        passive_path = tmp_path / "findings_passive.json"
        active_path = tmp_path / "findings_active.json"
        passive_path.write_text(json.dumps(passive))
        active_path.write_text(json.dumps(active))

        crew = ReconCrew(target="test.example.com")
        stats = crew._gather_stats({
            "passive_json": str(passive_path),
            "active_json": str(active_path),
        })

        assert stats["total_findings"] > 0, "total_findings must be > 0"
        assert stats["subdomains_count"] == 1
        assert stats["open_ports_count"] == 2
        # 3 missing headers: HSTS/CSP = High (2), X-Frame-Options = Medium (1)
        assert stats["high_count"] >= 2
        assert stats["medium_count"] >= 1


class TestPDFExport:
    def test_pdf_exported_with_xhtml2pdf(self, tmp_path):
        from tools.report.export_tool import export_report
        md = "# Test Report\n\n## Section\n\nContent with **bold** and `code`.\n\n| A | B |\n|---|---|\n| 1 | 2 |"
        result = json.loads(export_report.run(json.dumps({
            "markdown_content": md,
            "output_dir": str(tmp_path),
        })))
        assert result.get("pdf_exported"), f"PDF not exported: {result.get('errors', [])}"
        assert (tmp_path / "attack_surface_report.pdf").exists()


class TestTechStackFalsePositive:
    def test_cms_requires_multiple_signals(self):
        from unittest.mock import patch, MagicMock
        from tools.active.techstack_tool import technology_stack_analyzer

        # scanme.nmap.org-like response — no real CMS
        plain_html = """<html><head></head><body>
        <h1>Go ahead and ScanMe!</h1>
        <p>This is a service to allow you to test various network scanners.</p>
        </body></html>"""

        with patch("tools.active.http_helper.smart_request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.text = plain_html
            mock_resp.url = "http://scanme.nmap.org"
            mock_resp.status_code = 200
            mock_resp.headers = {"Server": "Apache/2.4.7 (Ubuntu)"}
            mock_req.return_value = mock_resp

            result = json.loads(technology_stack_analyzer.run("http://scanme.nmap.org"))
            # Should not detect Magento or any CMS for a plain HTML page
            assert result.get("cms") is None, f"False positive CMS detected: {result.get('cms')}"

    def test_cms_detected_with_strong_signals(self):
        from unittest.mock import patch, MagicMock
        from tools.active.techstack_tool import technology_stack_analyzer

        wp_html = """<html><head></head><body>
        <script src="/wp-content/themes/test/script.js"></script>
        <link href="/wp-includes/css/style.css" rel="stylesheet">
        </body></html>"""

        with patch("tools.active.http_helper.smart_request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.text = wp_html
            mock_resp.url = "http://example.com"
            mock_resp.status_code = 200
            mock_resp.headers = {}
            mock_req.return_value = mock_resp

            result = json.loads(technology_stack_analyzer.run("http://example.com"))
            assert result.get("cms") == "WordPress", f"WordPress not detected: {result}"


class TestViewDnsFilter:
    def test_filters_api_error_messages(self):
        import os
        from unittest.mock import patch, MagicMock
        from tools.passive.viewdns_tool import viewdns_lookup

        with patch("tools.passive.viewdns_tool.requests.get") as mock_get, \
             patch.dict(os.environ, {"VIEWDNS_API_KEY": ""}):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            # Mix of real domains and API error messages
            mock_resp.text = (
                "real-domain.com\n"
                "another.example.org\n"
                "API count exceeded - Increase Quota with Membership\n"
                "error: too many requests\n"
            )
            mock_get.return_value = mock_resp

            result = json.loads(viewdns_lookup.run("scanme.nmap.org"))
            domains = result.get("reverse_ip_domains", [])
            # Error messages must be filtered out
            for d in domains:
                assert "quota" not in d.lower(), f"API error not filtered: {d}"
                assert "api count" not in d.lower(), f"API error not filtered: {d}"
                assert "error:" not in d.lower(), f"Error line not filtered: {d}"
            assert "real-domain.com" in domains
            assert "another.example.org" in domains
