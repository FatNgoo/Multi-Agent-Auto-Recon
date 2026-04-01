# tools/active/finalize_tool.py
"""
Finalize active reconnaissance findings from cached data + compact summary.

This tool is called as the LAST STEP by the active recon agent.
It reads the URL cache saved by url_crawler and merges it with the
compact summary JSON provided by the agent, then writes findings_active.json.

This avoids the LLM needing to output a huge JSON with all_urls as its final
answer (which hits the max_tokens limit and produces truncated files).
"""
import json
import os
from datetime import datetime
from crewai.tools import tool

ACTIVE_PATH = "outputs/sessions/findings_active.json"
URL_CACHE = "outputs/sessions/_cache_urls.json"


@tool("Finalize Active Findings")
def finalize_active_findings(compact_json: str) -> str:
    """
    Hoàn tất và lưu active reconnaissance findings vào disk.
    Gộp all_urls từ cache file với compact summary JSON.
    Gọi tool này là BƯỚC CUỐI CÙNG của active recon task.
    Input: JSON string với tất cả active findings NGOẠI TRỪ all_urls.
    Bao gồm: target, scan_timestamp, hosts_scanned, open_ports,
    web_technologies, ssl_findings, missing_headers, waf_info,
    discovered_paths, discovered_params, cloud_assets, dangerous_methods,
    robots_txt_paths, favicon_hash, raw_active_notes.
    (all_urls được đọc tự động từ cache của url_crawler)
    """
    # Parse compact summary from agent
    try:
        summary = json.loads(compact_json)
    except Exception:
        summary = {}

    target = summary.get("target", "unknown")

    # Read URL cache saved by url_crawler tool
    all_urls = []
    if os.path.exists(URL_CACHE):
        try:
            with open(URL_CACHE, "r", encoding="utf-8") as f:
                all_urls = json.load(f)
        except Exception:
            pass

    # Build the final findings JSON
    findings = {
        "target": target,
        "scan_timestamp": summary.get("scan_timestamp", datetime.now().isoformat() + "Z"),
        "hosts_scanned": summary.get("hosts_scanned", []),
        "open_ports": summary.get("open_ports", {}),
        "web_technologies": summary.get("web_technologies", {}),
        "ssl_findings": summary.get("ssl_findings", []),
        "missing_headers": summary.get("missing_headers", {}),
        "waf_info": summary.get("waf_info", {}),
        "discovered_paths": summary.get("discovered_paths", {}),
        "discovered_params": summary.get("discovered_params", {}),
        "cloud_assets": summary.get("cloud_assets", {"s3_buckets": [], "azure_blobs": [], "gcs_buckets": []}),
        "dangerous_methods": summary.get("dangerous_methods", {}),
        "robots_txt_paths": summary.get("robots_txt_paths", {}),
        "favicon_hash": summary.get("favicon_hash", {}),
        "all_urls": all_urls,
        "raw_active_notes": summary.get("raw_active_notes", ""),
    }

    # Save to disk
    os.makedirs("outputs/sessions", exist_ok=True)
    try:
        with open(ACTIVE_PATH, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to save findings: {e}"})

    open_port_count = sum(
        len(ports) for ports in findings["open_ports"].values()
        if isinstance(ports, dict)
    )

    return json.dumps({
        "status": "success",
        "saved_to": ACTIVE_PATH,
        "target": target,
        "open_ports_count": open_port_count,
        "all_urls_count": len(all_urls),
        "scan_timestamp": findings["scan_timestamp"],
        "message": "Active findings saved successfully. Active recon task complete.",
    }, ensure_ascii=False)
