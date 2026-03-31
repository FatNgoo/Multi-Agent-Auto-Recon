# tools/passive/dnsdumpster_tool.py
import json
import requests
from crewai.tools import tool


@tool("DNSDumpster Lookup")
def dnsdumpster_lookup(domain: str) -> str:
    """
    Thu thập DNS mapping data qua HackerTarget API (DNSDumpster).
    Tìm host records, mail servers và DNS infrastructure của target.
    Input: tên miền (ví dụ: example.com)
    """
    try:
        # HackerTarget free API (rate limited at 100/day without key)
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(ht_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})

        hosts = []
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                parts = line.split(",")
                if len(parts) == 2:
                    hosts.append({"hostname": parts[0].strip(), "ip": parts[1].strip()})

        # DNSrecon-style via HackerTarget
        dns_url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        dns_resp = requests.get(dns_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})

        dns_records_raw = []
        if dns_resp.status_code == 200:
            dns_records_raw = [
                line.strip() for line in dns_resp.text.strip().splitlines()
                if line.strip() and "error" not in line.lower()
            ]

        return json.dumps({
            "domain": domain,
            "total_hosts": len(hosts),
            "hosts": hosts[:50],
            "dns_records_raw": dns_records_raw[:30],
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
