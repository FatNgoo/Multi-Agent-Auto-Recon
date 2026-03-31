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
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and "error" not in resp.text.lower():
            domains = [
                line.strip() for line in resp.text.strip().splitlines()
                if line.strip()
            ]
            results["reverse_ip_domains"] = domains[:30]
            results["reverse_ip_count"] = len(domains)
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
