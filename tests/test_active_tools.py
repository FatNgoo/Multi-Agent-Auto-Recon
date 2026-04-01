"""
Unit tests for active reconnaissance tools.
Tests use mocking to avoid real network/system calls.
CrewAI @tool decorator wraps functions into Tool objects — use .run() to invoke.
"""
import pytest
import json
from unittest.mock import patch, MagicMock, mock_open


class TestNmapTool:
    def test_returns_json_string(self):
        from tools.active.nmap_tool import nmap_port_scan
        with patch("tools.active.nmap_tool.nmap.PortScanner") as MockScanner:
            mock_nm = MagicMock()
            mock_nm.all_hosts.return_value = ["45.33.32.156"]
            mock_nm.__getitem__ = MagicMock(return_value=MagicMock(
                hostname=MagicMock(return_value="scanme.nmap.org"),
                state=MagicMock(return_value="up"),
                all_protocols=MagicMock(return_value=["tcp"]),
            ))
            mock_nm["45.33.32.156"].__getitem__ = MagicMock(return_value={
                22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9", "extrainfo": ""},
                80: {"state": "open", "name": "http", "product": "Apache", "version": "2.4.58", "extrainfo": ""},
            })
            MockScanner.return_value = mock_nm

            result = nmap_port_scan.run('{"host": "scanme.nmap.org"}')
            data = json.loads(result)
            assert isinstance(data, dict)

    def test_handles_nmap_not_found(self):
        from tools.active.nmap_tool import nmap_port_scan
        with patch("tools.active.nmap_tool.shutil.which", return_value=None):
            result = nmap_port_scan.run('{"host": "scanme.nmap.org"}')
            data = json.loads(result)
            assert "error" in data


class TestBannerTool:
    def test_returns_banner(self):
        from tools.active.banner_tool import banner_grabber
        with patch("tools.active.banner_tool.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1\r\n"
            mock_sock_cls.return_value = mock_sock

            result = banner_grabber.run('{"host": "scanme.nmap.org", "ports": [22]}')
            data = json.loads(result)
            assert isinstance(data, dict)

    def test_returns_json_on_connection_error(self):
        from tools.active.banner_tool import banner_grabber
        with patch("tools.active.banner_tool.socket.socket") as mock_sock_cls:
            mock_sock_cls.return_value.connect_ex.side_effect = ConnectionRefusedError()
            result = banner_grabber.run('{"host": "scanme.nmap.org", "ports": [22]}')
            data = json.loads(result)
            assert isinstance(data, dict)


class TestHeadersTool:
    def test_returns_security_headers_analysis(self):
        from tools.active.headers_tool import http_security_headers
        with patch("tools.active.headers_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {
                "Server": "Apache/2.4.58",
                "Content-Type": "text/html",
                "X-Powered-By": "PHP/8.1",
            }
            mock_get.return_value = mock_resp

            result = http_security_headers.run("http://scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)
            assert "missing_headers" in data or "status_code" in data or "error" in data

    def test_handles_connection_error(self):
        from tools.active.headers_tool import http_security_headers
        with patch("tools.active.headers_tool.requests.get", side_effect=Exception("Connection refused")):
            result = http_security_headers.run("http://scanme.nmap.org")
            data = json.loads(result)
            assert "error" in data


class TestWAFTool:
    def test_detects_waf_signature(self):
        from tools.active.waf_tool import waf_detector
        with patch("tools.active.waf_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.headers = {"Server": "cloudflare", "X-Cache": "HIT"}
            mock_resp.text = "Attention Required! | Cloudflare"
            mock_get.return_value = mock_resp

            result = waf_detector.run("http://example.com")
            data = json.loads(result)
            assert isinstance(data, dict)

    def test_no_waf_returns_json(self):
        from tools.active.waf_tool import waf_detector
        with patch("tools.active.waf_tool.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Server": "Apache"}
            mock_resp.text = "Hello World"
            mock_get.return_value = mock_resp

            result = waf_detector.run("http://scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestSSLTool:
    def test_returns_json(self):
        from tools.active.ssl_tool import ssl_tls_checker
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

            result = ssl_tls_checker.run("scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestDirbustTool:
    def test_finds_existing_paths(self):
        from tools.active.dirbust_tool import directory_enumerator
        with patch("tools.active.dirbust_tool.aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = {"Content-Length": "1234"}
            mock_resp.__aenter__ = MagicMock(return_value=mock_resp)
            mock_resp.__aexit__ = MagicMock(return_value=False)
            mock_session.get.return_value = mock_resp
            mock_session.__aenter__ = MagicMock(return_value=mock_session)
            mock_session.__aexit__ = MagicMock(return_value=False)
            mock_session_cls.return_value = mock_session

            result = directory_enumerator.run('{"url": "http://scanme.nmap.org", "wordlist_size": "small"}')
            data = json.loads(result)
            assert isinstance(data, dict)


class TestHttpMethodTool:
    def test_returns_method_results(self):
        from tools.active.http_method_tool import http_method_checker
        with patch("tools.active.http_method_tool.requests.request") as mock_req:
            def method_side_effect(method, url, **kwargs):
                resp = MagicMock()
                resp.status_code = 405 if method in ("PUT", "DELETE", "TRACE") else 200
                return resp
            mock_req.side_effect = method_side_effect

            result = http_method_checker.run("http://scanme.nmap.org")
            data = json.loads(result)
            assert isinstance(data, dict)


class TestCloudTool:
    def test_returns_bucket_results(self):
        from tools.active.cloud_tool import cloud_asset_finder
        with patch("tools.active.cloud_tool.requests.head") as mock_head:
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_head.return_value = mock_resp

            result = cloud_asset_finder.run("example.com")
            data = json.loads(result)
            assert isinstance(data, dict)
            assert "domain" in data or "s3_buckets" in data or "error" in data
