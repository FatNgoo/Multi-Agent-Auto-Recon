# tools/passive/finalize_tool.py
"""
Finalize passive reconnaissance findings from cached data + compact summary.

This tool is called as the LAST STEP by the passive recon agent.
It reads large-data caches saved by individual tools (subdomains, wayback URLs)
and merges them with the compact summary JSON provided by the agent,
then writes the final findings_passive.json to disk.

This avoids the LLM needing to output a huge JSON as its final answer
(which hits the max_tokens limit and produces truncated/corrupted files).
"""
import json
import os
from datetime import datetime
from crewai.tools import tool

PASSIVE_PATH = "outputs/sessions/findings_passive.json"
SUBDOMAIN_CACHE = "outputs/sessions/_cache_subdomains.json"
WAYBACK_CACHE = "outputs/sessions/_cache_wayback.json"


@tool("Finalize Passive Findings")
def finalize_passive_findings(compact_json: str) -> str:
    """
    Hoàn tất và lưu passive reconnaissance findings vào disk.
    Gộp dữ liệu từ các cache files (subdomains, wayback URLs) với compact summary.
    Gọi tool này là BƯỚC CUỐI CÙNG của passive recon task.
    Input: JSON string với các fields nhỏ: target, scan_timestamp, whois,
           dns_records, ssl_certificates, asn_info, shodan_data, osint_emails,
           google_dorks, reverse_ip_domains, related_domains, raw_passive_notes.
           KHÔNG cần include subdomains hay historical_urls (đọc từ cache).
    """
    # Parse compact summary from agent
    try:
        summary = json.loads(compact_json)
    except Exception as e:
        # Try to salvage partial JSON
        summary = {}

    target = summary.get("target", "unknown")

    # Read large-data caches saved by individual tools
    subdomains = []
    if os.path.exists(SUBDOMAIN_CACHE):
        try:
            with open(SUBDOMAIN_CACHE, "r", encoding="utf-8") as f:
                subdomains = json.load(f)
        except Exception:
            pass

    wayback_data = {}
    if os.path.exists(WAYBACK_CACHE):
        try:
            with open(WAYBACK_CACHE, "r", encoding="utf-8") as f:
                wayback_data = json.load(f)
        except Exception:
            pass

    # Build the final findings JSON
    findings = {
        "target": target,
        "scan_timestamp": summary.get("scan_timestamp", datetime.now().isoformat() + "Z"),
        "whois": summary.get("whois", {}),
        "dns_records": summary.get("dns_records", {}),
        "subdomains": subdomains,
        "ssl_certificates": summary.get("ssl_certificates", []),
        "asn_info": summary.get("asn_info", {}),
        "shodan_data": summary.get("shodan_data", {}),
        "osint_emails": summary.get("osint_emails", []),
        "google_dorks": summary.get("google_dorks", []),
        "historical_urls": wayback_data.get("interesting_urls", []),
        "reverse_ip_domains": summary.get("reverse_ip_domains", []),
        "related_domains": summary.get("related_domains", []),
        "raw_passive_notes": summary.get("raw_passive_notes", ""),
        # Extra wayback fields preserved as meta
        "wayback_meta": {
            "total_snapshots": wayback_data.get("total_snapshots", 0),
            "total_unique_urls": wayback_data.get("total_unique_urls", 0),
            "earliest_snapshot": wayback_data.get("earliest_snapshot"),
            "latest_snapshot": wayback_data.get("latest_snapshot"),
            "old_subdomains": wayback_data.get("old_subdomains", []),
            "file_exposures": wayback_data.get("file_exposures", []),
        },
    }

    # Merge wayback old_subdomains into subdomains list (avoid duplicates)
    existing_subs = {s.get("subdomain") for s in subdomains}
    for old_sub in wayback_data.get("old_subdomains", []):
        if old_sub and old_sub not in existing_subs:
            subdomains.append({"subdomain": old_sub, "ip": None, "source": "wayback"})
            existing_subs.add(old_sub)
    findings["subdomains"] = subdomains

    # Save to disk
    os.makedirs("outputs/sessions", exist_ok=True)
    try:
        with open(PASSIVE_PATH, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to save findings: {e}"})

    return json.dumps({
        "status": "success",
        "saved_to": PASSIVE_PATH,
        "target": target,
        "subdomains_count": len(subdomains),
        "scan_timestamp": findings["scan_timestamp"],
        "message": "Passive findings saved successfully. Passive recon task complete.",
    }, ensure_ascii=False)
