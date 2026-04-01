# tools/passive/viewdns_tool.py
import json
import os
import requests
from crewai.tools import tool


@tool("ViewDNS Reverse IP Lookup")
def viewdns_lookup(domain: str) -> str:
    """
    Thực hiện Reverse IP lookup và DNS history qua ViewDNS / HackerTarget API.
    Tìm các domain cùng IP server (shared hosting), lịch sử thay đổi IP.
    Input: tên miền hoặc IP address
    """
    results = {
        "input": domain,
        "reverse_ip_domains": [],
        "ip_history": [],
    }

    # Reverse IP via HackerTarget (free)
    # Known error/quota messages from HackerTarget that should never be treated as domain entries
    _HACKERTARGET_ERRORS = {
        "api count exceeded",
        "increase quota",
        "membership",
        "error:",
        "invalid",
        "no results",
        "too many requests",
    }

    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            raw_lines = [
                line.strip() for line in resp.text.strip().splitlines()
                if line.strip()
            ]
            # Filter out API error/quota messages
            domains = [
                line for line in raw_lines
                if not any(
                    err_kw in line.lower()
                    for err_kw in _HACKERTARGET_ERRORS
                )
                # Must look like a domain name (contains a dot and no spaces)
                and "." in line
                and " " not in line
            ]
            results["reverse_ip_domains"] = domains[:30]
            results["reverse_ip_count"] = len(domains)
            # Preserve any API error for transparency
            error_lines = [l for l in raw_lines if l not in domains]
            if error_lines:
                results["reverse_ip_api_note"] = "; ".join(error_lines[:3])
    except Exception as e:
        results["reverse_ip_error"] = str(e)

    # ViewDNS API (if key configured)
    api_key = os.getenv("VIEWDNS_API_KEY")
    if api_key:
        try:
            vdns_url = (
                f"https://api.viewdns.info/iphistory/"
                f"?domain={domain}&apikey={api_key}&output=json"
            )
            resp2 = requests.get(vdns_url, timeout=15)
            if resp2.status_code == 200:
                data = resp2.json()
                records = data.get("response", {}).get("records", [])
                results["ip_history"] = records[:20]
        except Exception as e:
            results["ip_history_error"] = str(e)
    else:
        results["ip_history_note"] = "VIEWDNS_API_KEY not set; IP history unavailable"

    return json.dumps(results, ensure_ascii=False, indent=2)
