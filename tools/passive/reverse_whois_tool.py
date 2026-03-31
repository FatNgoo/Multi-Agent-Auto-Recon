# tools/passive/reverse_whois_tool.py
import json
import os
import requests
from crewai.tools import tool


@tool("Reverse WHOIS Lookup")
def reverse_whois(domain: str) -> str:
    """
    Tìm các domain khác được đăng ký bởi cùng tổ chức qua Reverse WHOIS.
    Hữu ích để phát hiện toàn bộ attack surface của một tổ chức.
    Input: tên miền (ví dụ: example.com)
    """
    results = {
        "domain": domain,
        "related_domains": [],
        "method": None,
    }

    # Try Whoxy API (paid but cheap)
    whoxy_key = os.getenv("WHOXY_API_KEY")
    if whoxy_key:
        try:
            # First get WHOIS for the domain to find registrant email
            whois_url = f"https://api.whoxy.com/?key={whoxy_key}&whois={domain}"
            resp = requests.get(whois_url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                registrant_email = (
                    data.get("registrant_contact", {}).get("email_address") or
                    data.get("administrative_contact", {}).get("email_address")
                )
                if registrant_email:
                    # Reverse lookup by email
                    rev_url = (
                        f"https://api.whoxy.com/?key={whoxy_key}"
                        f"&reverse=whois&email={registrant_email}&mode=domains"
                    )
                    rev_resp = requests.get(rev_url, timeout=15)
                    if rev_resp.status_code == 200:
                        rev_data = rev_resp.json()
                        results["related_domains"] = rev_data.get("search_result", [])[:30]
                        results["registrant_email"] = registrant_email
                        results["method"] = "whoxy_api"
        except Exception as e:
            results["whoxy_error"] = str(e)

    # Fallback: HackerTarget (limited)
    if not results["related_domains"]:
        try:
            ht_url = f"https://api.hackertarget.com/whois/?q={domain}"
            resp = requests.get(ht_url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                results["whois_raw"] = resp.text[:500]
                results["method"] = "hackertarget_whois"
        except Exception:
            pass

    if not results["related_domains"] and not whoxy_key:
        results["note"] = "Set WHOXY_API_KEY for full reverse WHOIS functionality"

    return json.dumps(results, ensure_ascii=False, indent=2)
