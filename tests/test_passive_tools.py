"""
Unit tests for passive reconnaissance tools.
Tests use mocking to avoid real network calls.
"""
import pytest
import json
from unittest.mock import patch, MagicMock


class TestWhoisTool:
    def test_returns_json_string(self):
        """whois_lookup must return a JSON-parseable string."""
        from tools.passive.whois_tool import whois_lookup
        with patch("tools.passive.whois_tool.whois.whois") as mock_whois:
            mock_data = MagicMock()
            mock_data.registrar = "Test Registrar"
            mock_data.creation_date = "2000-01-01"
            mock_data.expiration_date = "2030-01-01"
            mock_data.name_servers = ["ns1.test.com"]
            mock_data.status = "active"
            mock_whois.return_value = mock_data

            result = whois_lookup("example.com")
            data = json.loads(result)
            assert "registrar" in data or "error" in data

    def test_handles_invalid_domain(self):
        """Should return error JSON on invalid domain."""
        from tools.passive.whois_tool import whois_lookup
        with patch("tools.passive.whois_tool.whois.whois", side_effect=Exception("NXDOMAIN")):
            result = whois_lookup("thisdoesnotexist12345.invalid")
            data = json.loads(result)
            assert "error" in data


class TestDNSTool:
    def test_returns_json_string(self):
        from tools.passive.dns_tool import dns_lookup
        with patch("tools.passive.dns_tool.dns.resolver.Resolver") as MockResolver:
            mock_res = MagicMock()
            mock_res.resolve.return_value = [MagicMock(address="1.2.3.4")]
            MockResolver.return_value = mock_res

            result = dns_lookup("example.com")
            data = json.loads(result)
            assert isinstance(data, dict)

    def test_handles_nxdomain(self):
        from tools.passive.dns_tool import dns_lookup
        import dns.resolver
        with patch("tools.passive.dns_tool.dns.resolver.Resolver") as MockResolver:
            mock_res = MagicMock()
            mock_res.resolve.side_effect = dns.resolver.NXDOMAIN()
            MockResolver.return_value = mock_res

            result = dns_lookup("thisdoesnotexist99999.invalid")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestSubdomainTool:
    def test_returns_json_string(self):
        from tools.passive.subdomain_tool import enumerate_subdomains
        with patch("tools.passive.subdomain_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                {"name_value": "www.example.com"},
                {"name_value": "mail.example.com"},
            ]
            mock_get.return_value = mock_resp

            result = enumerate_subdomains("example.com")
            data = json.loads(result)
            assert isinstance(data, list) or isinstance(data, dict)

    def test_returns_json_on_network_error(self):
        from tools.passive.subdomain_tool import enumerate_subdomains
        with patch("tools.passive.subdomain_tool.requests.get", side_effect=Exception("Timeout")):
            result = enumerate_subdomains("example.com")
            data = json.loads(result)
            assert isinstance(data, (dict, list))


class TestCertificateTool:
    def test_returns_json(self):
        from tools.passive.certificate_tool import check_certificates
        with patch("tools.passive.certificate_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                {
                    "id": 123456,
                    "name_value": "*.example.com\nexample.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "not_before": "2024-01-01",
                    "not_after": "2024-04-01",
                }
            ]
            mock_get.return_value = mock_resp

            result = check_certificates("example.com")
            data = json.loads(result)
            assert isinstance(data, (list, dict))


class TestIPASNTool:
    def test_returns_asn_data(self):
        from tools.passive.ip_asn_tool import lookup_ip_asn
        with patch("tools.passive.ip_asn_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "ip": "1.2.3.4",
                "org": "AS12345 Test ISP",
                "country": "US",
            }
            mock_get.return_value = mock_resp

            result = lookup_ip_asn("example.com")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestWaybackTool:
    def test_returns_json(self):
        from tools.passive.wayback_tool import wayback_lookup
        with patch("tools.passive.wayback_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
                ["com,example)/", "20240101120000", "http://example.com/", "text/html", "200", "ABCD1234", "5000"],
            ]
            mock_get.return_value = mock_resp

            result = wayback_lookup("example.com")
            data = json.loads(result)
            assert isinstance(data, (list, dict))
