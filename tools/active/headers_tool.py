# tools/active/headers_tool.py
import json
import requests
from crewai.tools import tool

HEADERS_CONFIG = {
    "Strict-Transport-Security": {
        "severity_missing": "High",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "min_max_age": 31536000,
    },
    "Content-Security-Policy": {
        "severity_missing": "High",
        "recommendation": "Add a strict Content-Security-Policy to prevent XSS",
        "unsafe_patterns": ["unsafe-inline", "unsafe-eval"],
    },
    "X-Frame-Options": {
        "severity_missing": "Medium",
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
    },
    "X-Content-Type-Options": {
        "severity_missing": "Low",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity_missing": "Low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity_missing": "Low",
        "recommendation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

_REQUESTS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}


@tool("HTTP Security Headers Checker")
def http_security_headers(url: str) -> str:
    """
    Phân tích HTTP security headers của web application.
    Phát hiện missing hoặc mis-configured headers: HSTS, CSP, X-Frame-Options, etc.
    Input: URL (ví dụ: https://example.com)
    """
    from tools.active.http_helper import normalize_url, smart_request
    url = normalize_url(url)

    try:
        resp = smart_request(url, timeout=15, headers=_REQUESTS_HEADERS)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        issues = []
        headers_found = {}

        for header, config in HEADERS_CONFIG.items():
            header_lower = header.lower()
            value = headers.get(header_lower)
            headers_found[header] = value

            if not value:
                issues.append({
                    "header": header,
                    "present": False,
                    "severity": config["severity_missing"],
                    "current_value": None,
                    "recommendation": config["recommendation"],
                })
            else:
                value_lower = value.lower()
                # CSP unsafe patterns
                if header == "Content-Security-Policy":
                    for pattern in config.get("unsafe_patterns", []):
                        if pattern in value_lower:
                            issues.append({
                                "header": header,
                                "present": True,
                                "severity": "Medium",
                                "current_value": value,
                                "recommendation": f"Remove '{pattern}' from CSP",
                            })
                # HSTS max-age check
                elif header == "Strict-Transport-Security":
                    import re
                    match = re.search(r"max-age=(\d+)", value_lower)
                    if match:
                        max_age = int(match.group(1))
                        if max_age < config["min_max_age"]:
                            issues.append({
                                "header": header,
                                "present": True,
                                "severity": "Medium",
                                "current_value": value,
                                "recommendation": f"Increase max-age to at least {config['min_max_age']}",
                            })

        # Information disclosure headers
        info_headers = {
            "server": headers.get("server", ""),
            "x-powered-by": headers.get("x-powered-by", ""),
            "x-aspnet-version": headers.get("x-aspnet-version", ""),
            "via": headers.get("via", ""),
        }
        for h_name, h_val in info_headers.items():
            if h_val:
                issues.append({
                    "header": h_name,
                    "present": True,
                    "severity": "Low",
                    "current_value": h_val,
                    "recommendation": f"Remove or sanitize {h_name} header (information disclosure)",
                })

        # Score calculation
        high_count = sum(1 for i in issues if i["severity"] == "High")
        medium_count = sum(1 for i in issues if i["severity"] == "Medium")
        score = 100 - (high_count * 15) - (medium_count * 5)
        score = max(0, score)

        if score >= 80:
            grade = "A"
        elif score >= 60:
            grade = "B"
        elif score >= 40:
            grade = "C"
        elif score >= 20:
            grade = "D"
        else:
            grade = "F"

        return json.dumps({
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "headers_found": headers_found,
            "issues": issues,
            "score": f"{score}/100",
            "grade": grade,
            "total_issues": len(issues),
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "url": url})
