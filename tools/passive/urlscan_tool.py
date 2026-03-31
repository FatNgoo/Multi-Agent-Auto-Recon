# tools/passive/urlscan_tool.py
import json
import os
import requests
from crewai.tools import tool


@tool("URLScan Passive Web Surface")
def urlscan_passive(domain: str) -> str:
    """
    Truy vấn URLScan.io để lấy passive web reconnaissance data.
    Cung cấp thông tin về technologies, URLs, screenshots, và security headers.
    Input: tên miền (ví dụ: example.com)
    """
    api_key = os.getenv("URLSCAN_API_KEY")
    headers = {"User-Agent": "Mozilla/5.0"}
    if api_key:
        headers["API-Key"] = api_key

    try:
        # Search existing scans
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10"
        resp = requests.get(search_url, headers=headers, timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            results_raw = data.get("results", [])

            scans = []
            for r in results_raw[:5]:
                page = r.get("page", {})
                stats = r.get("stats", {})
                meta = r.get("meta", {})
                scans.append({
                    "scan_id": r.get("_id"),
                    "url": page.get("url"),
                    "ip": page.get("ip"),
                    "server": page.get("server"),
                    "status": page.get("status"),
                    "country": page.get("country"),
                    "title": page.get("title"),
                    "asn": page.get("asn"),
                    "scan_date": r.get("task", {}).get("time"),
                    "requests_count": stats.get("requests"),
                    "technologies": meta.get("processors", {}).get("wappa", {}).get("data", []),
                })

            return json.dumps({
                "domain": domain,
                "total_scans_found": data.get("total", 0),
                "recent_scans": scans,
            }, ensure_ascii=False, indent=2)

        elif resp.status_code == 401:
            return json.dumps({
                "status": "unauthorized",
                "error": "Invalid URLSCAN_API_KEY",
                "domain": domain
            })
        else:
            return json.dumps({
                "status": "error",
                "http_code": resp.status_code,
                "domain": domain
            })

    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
