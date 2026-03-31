# tools/active/http_method_tool.py
import json
import requests
from crewai.tools import tool


DANGEROUS_METHODS = {
    "PUT": "Can upload arbitrary files to server",
    "DELETE": "Can delete files on server",
    "TRACE": "Cross-Site Tracing (XST) attack vector",
    "CONNECT": "Can be abused as HTTP proxy tunnel",
    "DEBUG": "Microsoft IIS debug mode - information disclosure",
    "PATCH": "Partial resource modification without proper auth checks",
}


@tool("HTTP Dangerous Methods Checker")
def http_method_checker(url: str) -> str:
    """
    Kiểm tra các HTTP methods nguy hiểm được kích hoạt trên server.
    PUT/DELETE có thể cho phép upload/xóa files. TRACE gây XST attack.
    OPTIONS tiết lộ supported methods. CONNECT dùng cho proxy abuse.
    Input: URL của target (ví dụ: https://example.com)
    """
    from tools.active.http_helper import normalize_url
    url = normalize_url(url)

    url = url.rstrip("/")

    methods_to_test = [
        "GET", "POST", "PUT", "DELETE", "PATCH",
        "OPTIONS", "HEAD", "TRACE", "CONNECT", "DEBUG",
    ]

    results = {
        "url": url,
        "methods_tested": [],
        "methods_allowed": [],
        "dangerous_methods_found": [],
        "options_header": None,
        "errors": [],
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Security Assessment Tool)",
    }

    # Check OPTIONS header first
    try:
        resp = requests.options(url, headers=headers, timeout=8, verify=False)
        allow_header = resp.headers.get("Allow", "")
        if allow_header:
            results["options_header"] = allow_header
    except Exception:
        pass

    # Test each method
    for method in methods_to_test:
        try:
            resp = requests.request(
                method, url,
                headers=headers,
                timeout=8,
                verify=False,
                allow_redirects=False,
            )

            enabled = resp.status_code not in [405, 501, 400, 501]

            entry = {
                "method": method,
                "status_code": resp.status_code,
                "enabled": enabled,
            }

            if enabled and method in DANGEROUS_METHODS:
                entry["risk"] = DANGEROUS_METHODS[method]
                entry["severity"] = (
                    "High" if method in ["PUT", "DELETE", "DEBUG"]
                    else "Medium"
                )
                results["dangerous_methods_found"].append(entry)

            if enabled:
                results["methods_allowed"].append(method)

            results["methods_tested"].append(entry)

        except requests.exceptions.ConnectionError:
            results["errors"].append(f"{method}: Connection refused")
        except requests.exceptions.Timeout:
            results["errors"].append(f"{method}: Timeout")
        except Exception as e:
            results["methods_tested"].append({
                "method": method,
                "status_code": None,
                "enabled": False,
                "error": str(e),
            })

    dangerous_found = [m["method"] for m in results["dangerous_methods_found"]]
    results["risk_summary"] = (
        f"Found {len(dangerous_found)} dangerous methods: {dangerous_found}"
        if dangerous_found
        else "No dangerous methods found"
    )

    results["severity"] = (
        "High" if any(m in dangerous_found for m in ["PUT", "DELETE", "DEBUG"])
        else "Medium" if dangerous_found
        else "Info"
    )

    return json.dumps(results, ensure_ascii=False, indent=2)
