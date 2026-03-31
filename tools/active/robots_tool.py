# tools/active/robots_tool.py
import json
import requests
import xml.etree.ElementTree as ET
from crewai.tools import tool

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}


@tool("Robots.txt and Sitemap Parser")
def robots_sitemap_parser(url: str) -> str:
    """
    Phân tích robots.txt và sitemap.xml để tìm hidden paths, API endpoints.
    Disallowed paths thường chứa admin panels và sensitive content.
    Input: base URL (ví dụ: https://example.com)
    """
    from tools.active.http_helper import normalize_url
    url = normalize_url(url)
    base_url = "/".join(url.split("/")[:3])

    result = {
        "base_url": base_url,
        "robots_txt": {
            "found": False,
            "disallowed": [],
            "allowed": [],
            "sitemaps": [],
            "user_agents": [],
            "raw": None,
        },
        "sitemaps": [],
        "interesting_paths": [],
    }

    # Parse robots.txt
    try:
        robots_resp = requests.get(
            f"{base_url}/robots.txt", headers=_HEADERS, timeout=8, verify=False
        )
        if robots_resp.status_code == 200:
            result["robots_txt"]["found"] = True
            result["robots_txt"]["raw"] = robots_resp.text[:2000]

            disallowed = []
            allowed = []
            sitemaps = []
            user_agents = []

            for line in robots_resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        allowed.append(path)
                elif line.lower().startswith("sitemap:"):
                    sm_url = line.split(":", 1)[1].strip()
                    sitemaps.append(sm_url)
                elif line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()
                    user_agents.append(ua)

            result["robots_txt"]["disallowed"] = disallowed
            result["robots_txt"]["allowed"] = allowed
            result["robots_txt"]["sitemaps"] = sitemaps
            result["robots_txt"]["user_agents"] = user_agents

            # Flag interesting disallowed paths
            sensitive_keywords = [
                "admin", "login", "api", "backup", "config", "private",
                "secret", "internal", "staging", "dev", "test", "upload"
            ]
            for path in disallowed:
                for kw in sensitive_keywords:
                    if kw in path.lower():
                        result["interesting_paths"].append({
                            "path": path,
                            "source": "robots.txt disallow",
                            "reason": f"Sensitive keyword: {kw}",
                        })
                        break

    except Exception as e:
        result["robots_txt"]["error"] = str(e)

    # Parse sitemap(s)
    sitemap_urls = result["robots_txt"]["sitemaps"] or [f"{base_url}/sitemap.xml"]

    for sm_url in sitemap_urls[:3]:  # Process up to 3 sitemaps
        try:
            sm_resp = requests.get(sm_url, headers=_HEADERS, timeout=8, verify=False)
            if sm_resp.status_code == 200:
                sm_entry = {"url": sm_url, "urls_found": [], "sub_sitemaps": []}
                try:
                    root = ET.fromstring(sm_resp.content)
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    # Regular sitemap
                    for url_tag in root.findall("sm:url", ns):
                        loc = url_tag.findtext("sm:loc", namespaces=ns)
                        if loc:
                            sm_entry["urls_found"].append(loc)
                    # Sitemap index
                    for sitemap_tag in root.findall("sm:sitemap", ns):
                        loc = sitemap_tag.findtext("sm:loc", namespaces=ns)
                        if loc:
                            sm_entry["sub_sitemaps"].append(loc)
                except ET.ParseError:
                    # Might be text sitemap
                    sm_entry["urls_found"] = [
                        line.strip() for line in sm_resp.text.splitlines()
                        if line.strip().startswith("http")
                    ][:100]

                sm_entry["total_urls"] = len(sm_entry["urls_found"])
                sm_entry["urls_found"] = sm_entry["urls_found"][:50]  # Limit output
                result["sitemaps"].append(sm_entry)
        except Exception:
            pass

    return json.dumps(result, ensure_ascii=False, indent=2)
