# tools/passive/google_dork_tool.py
import json
import time
import requests
from crewai.tools import tool


@tool("Google Dorking")
def google_dorking(domain: str) -> str:
    """
    Thực hiện passive Google dork queries để tìm thông tin nhạy cảm.
    Tìm file exposures, login pages, directory listings, API endpoints.
    Input: tên miền (ví dụ: example.com)
    """
    dork_queries = [
        (f"site:{domain} filetype:pdf", "PDF documents"),
        (f"site:{domain} filetype:xls OR filetype:xlsx", "Spreadsheets"),
        (f"site:{domain} inurl:admin OR inurl:login OR inurl:dashboard", "Admin/Login pages"),
        (f"site:{domain} intext:\"index of\"", "Directory listings"),
        (f"site:{domain} ext:env OR ext:config OR ext:cfg", "Config files"),
        (f"site:{domain} inurl:api OR inurl:swagger OR inurl:graphql", "API endpoints"),
        (f"site:{domain} intext:password OR intext:secret OR intext:token", "Sensitive data"),
        (f"site:{domain} -www", "Non-www subdomains"),
    ]

    results = []

    # Try googlesearch-python if available
    try:
        from googlesearch import search

        for query, description in dork_queries:
            hits = []
            try:
                for url in search(query, num_results=5, pause=2.5, lang="en"):
                    hits.append(url)
                time.sleep(2.5)
            except Exception as e:
                error_str = str(e).lower()
                if "429" in error_str or "rate" in error_str or "too many" in error_str:
                    results.append({
                        "dork": query,
                        "description": description,
                        "hits": 0,
                        "results": [],
                        "note": "Rate limited by Google",
                    })
                    break

            results.append({
                "dork": query,
                "description": description,
                "hits": len(hits),
                "results": hits,
            })

    except ImportError:
        # Fallback: Use DuckDuckGo HTML scraping (no API key needed)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        for query, description in dork_queries:
            try:
                ddg_url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"
                resp = requests.get(ddg_url, headers=headers, timeout=10)
                import re
                urls = re.findall(r'href="(https?://[^"]+)"', resp.text)
                # Filter to likely real results
                filtered = [u for u in urls if domain in u and "duckduckgo" not in u][:5]
                results.append({
                    "dork": query,
                    "description": description,
                    "hits": len(filtered),
                    "results": filtered,
                    "source": "duckduckgo_html",
                })
                time.sleep(2)
            except Exception as e:
                results.append({
                    "dork": query,
                    "description": description,
                    "hits": 0,
                    "results": [],
                    "error": str(e),
                })

    notable = [r for r in results if r.get("hits", 0) > 0]

    return json.dumps({
        "domain": domain,
        "total_dorks_run": len(results),
        "dorks_with_results": len(notable),
        "dork_results": results,
    }, ensure_ascii=False, indent=2)
