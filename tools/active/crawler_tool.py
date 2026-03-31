# tools/active/crawler_tool.py
import json
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
from crewai.tools import tool

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}


@tool("URL Crawler")
def url_crawler(input_json: str) -> str:
    """
    Crawl website để khám phá tất cả accessible URLs.
    Tìm forms, API endpoints, interesting paths qua link following.
    Input: JSON string {"url": "https://target.com", "depth": 2, "max_urls": 100}
    """
    import json as _json
    try:
        params = _json.loads(input_json)
    except Exception:
        params = {"url": input_json.strip()}

    base_url = params.get("url", "")
    max_depth = min(int(params.get("depth", 2)), 3)
    max_urls = min(int(params.get("max_urls", 100)), 200)

    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc

    visited = set()
    to_visit = deque([(base_url, 0)])
    found_urls = []
    forms_found = []
    interesting = []

    while to_visit and len(found_urls) < max_urls:
        current_url, depth = to_visit.popleft()

        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        try:
            resp = requests.get(current_url, headers=_HEADERS, timeout=5,
                                allow_redirects=True, verify=False)
            found_urls.append({
                "url": current_url,
                "status": resp.status_code,
                "content_type": resp.headers.get("Content-Type", "")[:50],
                "depth": depth,
            })

            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Find forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                inputs = [(i.get("name", ""), i.get("type", "text"))
                          for i in form.find_all("input")]
                forms_found.append({
                    "page": current_url,
                    "action": urljoin(current_url, action),
                    "method": method,
                    "inputs": inputs[:10],
                })

            if depth < max_depth:
                # Extract links
                for tag in soup.find_all(["a", "link", "script", "img"]):
                    href = tag.get("href") or tag.get("src") or ""
                    if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
                        continue
                    abs_url = urljoin(current_url, href)
                    parsed = urlparse(abs_url)
                    if parsed.netloc == base_domain and abs_url not in visited:
                        to_visit.append((abs_url, depth + 1))

        except Exception:
            pass

    # Identify interesting URLs
    interesting_keywords = [
        "admin", "login", "api", "graphql", "swagger", "config",
        "backup", "upload", "download", "secret", "token", "key",
        "debug", "test", "dev", "staging", "internal",
    ]
    for url_entry in found_urls:
        url_lower = url_entry["url"].lower()
        for kw in interesting_keywords:
            if kw in url_lower:
                interesting.append({"url": url_entry["url"], "keyword": kw})
                break

    return json.dumps({
        "base_url": base_url,
        "total_urls_found": len(found_urls),
        "max_depth": max_depth,
        "urls": found_urls[:100],
        "forms": forms_found[:20],
        "interesting_urls": interesting[:30],
    }, ensure_ascii=False, indent=2)
