# tools/active/favicon_tool.py
import json
import base64
import re
import requests
from crewai.tools import tool

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


@tool("Favicon Hash Scanner")
def favicon_hasher(url: str) -> str:
    """
    Tính Favicon Hash (MurmurHash3) để tìm kiếm trên Shodan.
    Favicon hash giúp identify web applications và tìm related servers.
    Shodan query: http.favicon.hash:{hash_value}
    Input: URL (ví dụ: https://example.com)
    """
    from tools.active.http_helper import normalize_url, smart_request
    url = normalize_url(url)

    base_url = url.rstrip("/")
    favicon_url = f"{base_url}/favicon.ico"

    try:
        resp = smart_request(favicon_url, timeout=15, headers=_HEADERS)

        if resp.status_code != 200 or not resp.content:
            # Try to find favicon from HTML
            try:
                html_resp = requests.get(base_url, headers=_HEADERS, timeout=10, verify=False)
                matches = re.findall(
                    r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']',
                    html_resp.text, re.IGNORECASE
                )
                if matches:
                    favicon_path = matches[0]
                    if not favicon_path.startswith("http"):
                        favicon_url = base_url + "/" + favicon_path.lstrip("/")
                    else:
                        favicon_url = favicon_path
                    resp = requests.get(favicon_url, headers=_HEADERS, timeout=10, verify=False)
            except Exception:
                pass

        if resp.status_code == 200 and resp.content:
            favicon_b64 = base64.encodebytes(resp.content).decode("utf-8")

            if HAS_MMH3:
                favicon_hash = mmh3.hash(favicon_b64)
            else:
                # Fallback: use Python's built-in hash (not identical to shodan's but usable)
                favicon_hash = hash(favicon_b64) & 0xFFFFFFFF
                favicon_hash = favicon_hash if favicon_hash < 2**31 else favicon_hash - 2**32

            return json.dumps({
                "url": url,
                "favicon_url": favicon_url,
                "hash": favicon_hash,
                "shodan_query": f"http.favicon.hash:{favicon_hash}",
                "shodan_search_url": f"https://www.shodan.io/search?query=http.favicon.hash:{favicon_hash}",
                "size_bytes": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
                "mmh3_available": HAS_MMH3,
                "note": "Search Shodan with the query above to find servers with same favicon",
            }, indent=2)
        else:
            return json.dumps({
                "url": url,
                "hash": None,
                "error": f"Favicon not found (status: {resp.status_code})",
            })

    except Exception as e:
        return json.dumps({"error": str(e), "url": url})
