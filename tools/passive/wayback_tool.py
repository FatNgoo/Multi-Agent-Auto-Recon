# tools/passive/wayback_tool.py
import json
import requests
from crewai.tools import tool

INTERESTING_KEYWORDS = [
    "login", "admin", "password", "config", "backup", "test", "dev",
    "staging", "debug", "secret", "token", "api", "key", "credential",
]
INTERESTING_EXTENSIONS = [".zip", ".tar", ".bak", ".sql", ".env", ".git", ".log", ".conf"]


@tool("Wayback Machine History")
def wayback_machine(domain: str) -> str:
    """
    Thu thập lịch sử URLs từ Wayback Machine (Internet Archive).
    Tìm old URLs, deleted pages, historical tech stack và file exposures.
    Input: tên miền (ví dụ: example.com)
    """
    try:
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json"
            f"&fl=original,timestamp,statuscode"
            f"&limit=500&collapse=urlkey"
        )
        resp = requests.get(cdx_url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return json.dumps({"error": f"Wayback CDX returned {resp.status_code}", "domain": domain})

        raw = resp.json()
        if len(raw) <= 1:
            return json.dumps({
                "domain": domain,
                "total_snapshots": 0,
                "earliest_snapshot": None,
                "latest_snapshot": None,
                "interesting_urls": [],
                "old_subdomains": [],
                "file_exposures": [],
            })

        # First row is header
        headers_row = raw[0]
        rows = raw[1:]

        timestamps = [row[1] for row in rows if len(row) > 1]
        timestamps.sort()

        interesting_urls = []
        old_subdomains = set()
        file_exposures = []
        all_urls = set()

        for row in rows:
            if len(row) < 3:
                continue
            url, ts, status = row[0], row[1], row[2]
            all_urls.add(url)

            # Extract subdomains
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or ""
                if host and host != domain and domain in host:
                    old_subdomains.add(host)
            except Exception:
                pass

            # Interesting URLs by keyword
            url_lower = url.lower()
            for kw in INTERESTING_KEYWORDS:
                if kw in url_lower:
                    interesting_urls.append({
                        "url": url,
                        "timestamp": ts,
                        "status": status,
                        "reason": f"Keyword: {kw}",
                    })
                    break

            # File exposures
            for ext in INTERESTING_EXTENSIONS:
                if url_lower.endswith(ext) or f"{ext}?" in url_lower:
                    file_exposures.append({
                        "url": url,
                        "timestamp": ts,
                        "file_type": ext,
                    })
                    break

        wayback_result = {
            "domain": domain,
            "total_snapshots": len(rows),
            "total_unique_urls": len(all_urls),
            "earliest_snapshot": timestamps[0][:8] if timestamps else None,
            "latest_snapshot": timestamps[-1][:8] if timestamps else None,
            "interesting_urls": interesting_urls[:30],
            "old_subdomains": list(old_subdomains)[:20],
            "file_exposures": file_exposures[:20],
        }

        # Auto-save to cache so finalize_passive_findings can read it
        import os
        os.makedirs("outputs/sessions", exist_ok=True)
        cache_path = "outputs/sessions/_cache_wayback.json"
        try:
            with open(cache_path, "w", encoding="utf-8") as _f:
                import json as _json
                _json.dump(wayback_result, _f, ensure_ascii=False)
        except Exception:
            pass

        return json.dumps(wayback_result, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
