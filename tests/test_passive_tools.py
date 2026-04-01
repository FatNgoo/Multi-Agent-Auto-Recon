"""
Unit tests for passive reconnaissance tools.
Tests use mocking to avoid real network calls.
CrewAI @tool decorator wraps functions into Tool objects — use .run() to invoke.
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

            result = whois_lookup.run("example.com")
            data = json.loads(result)
            assert "registrar" in data or "error" in data

    def test_handles_invalid_domain(self):
        """Should return error JSON on invalid domain."""
        from tools.passive.whois_tool import whois_lookup
        with patch("tools.passive.whois_tool.whois.whois", side_effect=Exception("NXDOMAIN")):
            result = whois_lookup.run("thisdoesnotexist12345.invalid")
            data = json.loads(result)
            assert "error" in data


class TestDNSTool:
    def test_returns_json_string(self):
        from tools.passive.dns_tool import dns_enumeration
        import dns.resolver as _resolver

        class FakeRecord:
            def __init__(self, val):
                self._val = val
            def __str__(self):
                return self._val
            def rstrip(self, chars=""):
                return self._val.rstrip(chars)

        def mock_resolve(domain, rtype):
            if rtype == "A":
                return [FakeRecord("1.2.3.4")]
            raise _resolver.NoAnswer()

        with patch("tools.passive.dns_tool.dns.resolver.resolve", side_effect=mock_resolve):
            result = dns_enumeration.run("example.com")
            data = json.loads(result)
            assert isinstance(data, dict)
            assert "A" in data

    def test_handles_nxdomain(self):
        from tools.passive.dns_tool import dns_enumeration
        import dns.resolver
        with patch("tools.passive.dns_tool.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = dns_enumeration.run("thisdoesnotexist99999.invalid")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestSubdomainTool:
    def test_returns_json_string(self):
        from tools.passive.subdomain_tool import subdomain_finder
        with patch("tools.passive.subdomain_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                {"name_value": "www.example.com"},
                {"name_value": "mail.example.com"},
            ]
            mock_get.return_value = mock_resp

            result = subdomain_finder.run("example.com")
            data = json.loads(result)
            assert isinstance(data, list) or isinstance(data, dict)

    def test_returns_json_on_network_error(self):
        from tools.passive.subdomain_tool import subdomain_finder
        with patch("tools.passive.subdomain_tool.requests.get", side_effect=Exception("Timeout")):
            result = subdomain_finder.run("example.com")
            data = json.loads(result)
            assert isinstance(data, (dict, list))


class TestCertificateTool:
    def test_returns_json(self):
        from tools.passive.certificate_tool import certificate_transparency
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

            result = certificate_transparency.run("example.com")
            data = json.loads(result)
            assert isinstance(data, (list, dict))


class TestIPASNTool:
    def test_returns_asn_data(self):
        from tools.passive.ip_asn_tool import ip_asn_lookup
        with patch("tools.passive.ip_asn_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "ip": "1.2.3.4",
                "org": "AS12345 Test ISP",
                "country": "US",
            }
            mock_get.return_value = mock_resp

            result = ip_asn_lookup.run("example.com")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestWaybackTool:
    def test_returns_json(self):
        from tools.passive.wayback_tool import wayback_machine
        with patch("tools.passive.wayback_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
                ["com,example)/", "20240101120000", "http://example.com/", "text/html", "200", "ABCD1234", "5000"],
            ]
            mock_get.return_value = mock_resp

            result = wayback_machine.run("example.com")
            data = json.loads(result)
            assert isinstance(data, (list, dict))
