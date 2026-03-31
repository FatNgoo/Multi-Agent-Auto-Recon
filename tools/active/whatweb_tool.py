# tools/active/whatweb_tool.py
import json
import re
import requests
from bs4 import BeautifulSoup
from crewai.tools import tool

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"/wp-json/", r"WordPress"],
    "Drupal": [r"Drupal", r"/sites/default/files/", r"drupal.js"],
    "Joomla": [r"Joomla!", r"/components/com_", r"option=com_"],
    "Laravel": [r"laravel_session", r"X-Powered-By: PHP/", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"Django"],
    "React": [r"react-dom", r"__REACT_DEVTOOLS"],
    "Angular": [r"ng-version", r"angular.min.js"],
    "Vue.js": [r"__vue__", r"vue.min.js", r"<div.*v-"],
    "jQuery": [r"jquery\.min\.js", r"jquery-\d"],
    "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
    "nginx": [r"Server: nginx", r"server: nginx"],
    "Apache": [r"Server: Apache", r"server: apache"],
    "IIS": [r"Server: Microsoft-IIS", r"X-Powered-By: ASP\.NET"],
    "PHP": [r"X-Powered-By: PHP", r"\.php", r"PHPSESSID"],
    "ASP.NET": [r"X-Powered-By: ASP\.NET", r"__VIEWSTATE", r"\.aspx"],
    "Node.js": [r"X-Powered-By: Express", r"X-Powered-By: node"],
    "Cloudflare": [r"cf-ray", r"__cfduid", r"cloudflare"],
    "AWS CloudFront": [r"X-Amz-Cf-Id", r"x-amz-cf-id", r"CloudFront"],
    "Google Analytics": [r"google-analytics\.com/analytics\.js", r"gtag\("],
    "Shopify": [r"Shopify\.theme", r"cdn\.shopify\.com"],
    "Magento": [r"Mage\.Cookies", r"var BLANK_URL.*mage"],
}


@tool("WhatWeb Technology Fingerprinter")
def whatweb_fingerprint(url: str) -> str:
    """
    Fingerprint web technologies: CMS, frameworks, server software, libraries.
    Phân tích HTML, headers và scripts để xác định tech stack.
    Input: URL (ví dụ: https://example.com)
    """
    from tools.active.http_helper import normalize_url, smart_request
    url = normalize_url(url)

    try:
        resp = smart_request(url, timeout=15, headers=HEADERS)

        body = resp.text
        headers_str = str(resp.headers)
        combined = body + headers_str

        detected = {}
        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected[tech] = True
                    break

        # Extract meta generator
        soup = BeautifulSoup(body, "html.parser")
        generator_meta = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        generator = generator_meta.get("content", "") if generator_meta else ""

        # Extract title
        title_tag = soup.find("title")
        page_title = title_tag.get_text(strip=True) if title_tag else ""

        # Extract server header
        server = resp.headers.get("Server", "") or resp.headers.get("server", "")
        powered_by = resp.headers.get("X-Powered-By", "")

        return json.dumps({
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "page_title": page_title,
            "server": server,
            "powered_by": powered_by,
            "generator": generator,
            "technologies_detected": list(detected.keys()),
            "tech_count": len(detected),
            "content_type": resp.headers.get("Content-Type", ""),
        }, ensure_ascii=False, indent=2)

    except requests.exceptions.SSLError:
        # Retry without SSL verification
        try:
            import urllib3
            urllib3.disable_warnings()
            resp = requests.get(url, headers=HEADERS, timeout=15,
                                allow_redirects=True, verify=False)
            return whatweb_fingerprint.__wrapped__(url)
        except Exception:
            pass
        return json.dumps({"error": "SSL error", "url": url})
    except Exception as e:
        return json.dumps({"error": str(e), "url": url})
