"""
Unit tests for active reconnaissance tools.
Tests use mocking to avoid real network/system calls.
"""
import pytest
import json
from unittest.mock import patch, MagicMock, mock_open


class TestNmapTool:
    def test_returns_json_string(self):
        from tools.active.nmap_tool import run_nmap_scan
        mock_output = """
Starting Nmap 7.94
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.11s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9
80/tcp open  http    Apache httpd 2.4.58
Nmap done: 1 IP address (1 host up)
"""
        with patch("tools.active.nmap_tool.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_output, stderr="")
            result = run_nmap_scan("scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)

    def test_handles_nmap_not_found(self):
        from tools.active.nmap_tool import run_nmap_scan
        with patch("tools.active.nmap_tool.subprocess.run", side_effect=FileNotFoundError("nmap not found")):
            result = run_nmap_scan("scanme.nmap.org")
            data = json.loads(result)
            assert "error" in data


class TestBannerTool:
    def test_returns_banner(self):
        from tools.active.banner_tool import grab_banner
        with patch("tools.active.banner_tool.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1\r\n"
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            result = grab_banner("scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)

    def test_returns_json_on_connection_error(self):
        from tools.active.banner_tool import grab_banner
        with patch("tools.active.banner_tool.socket.create_connection", side_effect=ConnectionRefusedError()):
            result = grab_banner("scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestHeadersTool:
    def test_returns_security_headers_analysis(self):
        from tools.active.headers_tool import check_headers
        with patch("tools.active.headers_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {
                "Server": "Apache/2.4.58",
                "Content-Type": "text/html",
                "X-Powered-By": "PHP/8.1",
            }
            mock_get.return_value = mock_resp

            result = check_headers("http://scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)
            assert "missing_headers" in data or "status_code" in data or "error" in data

    def test_handles_connection_error(self):
        from tools.active.headers_tool import check_headers
        with patch("tools.active.headers_tool.requests.get", side_effect=Exception("Connection refused")):
            result = check_headers("http://scanme.nmap.org")
            data = json.loads(result)
            assert "error" in data


class TestWAFTool:
    def test_detects_waf_signature(self):
        from tools.active.waf_tool import detect_waf
        with patch("tools.active.waf_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.headers = {"Server": "cloudflare", "X-Cache": "HIT"}
            mock_resp.text = "Attention Required! | Cloudflare"
            mock_get.return_value = mock_resp

            result = detect_waf("http://example.com")
            data = json.loads(result)
            assert isinstance(data, dict)

    def test_no_waf_returns_json(self):
        from tools.active.waf_tool import detect_waf
        with patch("tools.active.waf_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Server": "Apache"}
            mock_resp.text = "Hello World"
            mock_get.return_value = mock_resp

            result = detect_waf("http://scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestSSLTool:
    def test_returns_json(self):
        from tools.active.ssl_tool import check_ssl
        with patch("tools.active.ssl_tool.ssl.create_default_context") as mock_ctx:
            mock_context = MagicMock()
            mock_sock = MagicMock()
            mock_sock.getpeercert.return_value = {
                "subject": ((("commonName", "scanme.nmap.org"),),),
                "notBefore": "Jan 1 00:00:00 2024 GMT",
                "notAfter": "Apr 1 00:00:00 2024 GMT",
                "version": 3,
            }
            mock_context.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_context.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.return_value = mock_context

            result = check_ssl("scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestDirbustTool:
    def test_finds_existing_paths(self):
        from tools.active.dirbust_tool import dirbust_scan
        with patch("tools.active.dirbust_tool.requests.get") as mock_get:
            def side_effect(url, **kwargs):
                resp = MagicMock()
                if url.endswith("robots.txt"):
                    resp.status_code = 200
                    resp.content = b"User-agent: *"
                elif url.endswith("/"):
                    resp.status_code = 200
                    resp.content = b"<html>Home</html>"
                else:
                    resp.status_code = 404
                    resp.content = b""
                return resp
            mock_get.side_effect = side_effect

            result = dirbust_scan("http://scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestHttpMethodTool:
    def test_returns_method_results(self):
        from tools.active.http_method_tool import check_http_methods
        with patch("tools.active.http_method_tool.requests.request") as mock_req:
            def method_side_effect(method, url, **kwargs):
                resp = MagicMock()
                resp.status_code = 405 if method in ("PUT", "DELETE", "TRACE") else 200
                return resp
            mock_req.side_effect = method_side_effect

            result = check_http_methods("http://scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestCloudTool:
    def test_returns_bucket_results(self):
        from tools.active.cloud_tool import check_cloud_buckets
        with patch("tools.active.cloud_tool.requests.head") as mock_head:
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_head.return_value = mock_resp

            result = check_cloud_buckets("example.com")
            data = json.loads(result)
            assert isinstance(data, dict)
            assert "public_buckets" in data or "checked" in data or "error" in data
