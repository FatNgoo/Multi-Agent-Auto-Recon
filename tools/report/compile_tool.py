# tools/report/compile_tool.py
import json
from datetime import datetime
from crewai.tools import tool


@tool("Compile All Findings")
def compile_all_findings(input_json: str) -> str:
    """
    Tổng hợp và normalize toàn bộ findings từ passive và active recon
    thành một dataset thống nhất sẵn sàng cho CVE lookup và báo cáo.
    Input: JSON string {"passive": {...}, "active": {...}}
    """
    try:
        data = json.loads(input_json)
        passive = data.get("passive", {})
        active = data.get("active", {})
    except Exception:
        # Try to handle if just one findings object passed
        try:
            data = json.loads(input_json)
            passive = data
            active = {}
        except Exception:
            return json.dumps({"error": "Invalid JSON input"})

    compiled = {
        "meta": {
            "target": passive.get("target", active.get("target", "unknown")),
            "compiled_at": datetime.now().isoformat(),
            "passive_scan_time": passive.get("scan_timestamp"),
            "active_scan_time": active.get("scan_timestamp"),
        },
        "infrastructure": {
            "primary_domain": passive.get("target"),
            "subdomains": [s["subdomain"] if isinstance(s, dict) else s
                           for s in passive.get("subdomains", [])],
            "ip_addresses": list(set([
                s["ip"] for s in passive.get("subdomains", [])
                if isinstance(s, dict) and s.get("ip")
            ])),
            "asn": passive.get("asn_info", {}).get("asn"),
            "asn_org": passive.get("asn_info", {}).get("org"),
            "cidr_ranges": passive.get("asn_info", {}).get("cidr", []),
        },
        "services": [],
        "web_findings": [],
        "osint_findings": [],
        "infrastructure_findings": [],
    }

    # Extract services from active scan open ports
    for host, ports in active.get("open_ports", {}).items():
        if isinstance(ports, dict):
            for port_num, port_info in ports.items():
                if isinstance(port_info, dict):
                    service_entry = {
                        "host": host,
                        "port": int(port_num) if str(port_num).isdigit() else port_num,
                        "protocol": port_info.get("protocol", "tcp"),
                        "service": port_info.get("service", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "banner": port_info.get("banner", ""),
                        "category": "network",
                        "severity": "Info",
                        "cvss_score": 0.0,
                        "cves": [],
                    }
                    compiled["services"].append(service_entry)

    # Web findings: SSL issues
    for finding in active.get("ssl_findings", []):
        if isinstance(finding, dict):
            compiled["web_findings"].append({
                "category": "ssl_tls",
                "host": finding.get("host"),
                "title": f"SSL/TLS Issue: {finding.get('issue', 'Configuration problem')}",
                "detail": finding,
                "severity": (
                    "Critical" if finding.get("cert_expiry_days", 9999) < 0
                    else "High" if "1.0" in str(finding.get("tls_versions", [])) or finding.get("cert_expiry_days", 9999) < 30
                    else "Medium"
                ),
            })

    # Web findings: Missing headers
    for host, headers in active.get("missing_headers", {}).items():
        if isinstance(headers, list):
            for header in headers:
                compiled["web_findings"].append({
                    "category": "security_headers",
                    "host": host,
                    "title": f"Missing Security Header: {header}",
                    "severity": (
                        "High" if header in ["Strict-Transport-Security", "Content-Security-Policy"]
                        else "Medium"
                    ),
                    "detail": {"missing_header": header, "host": host},
                })

    # OSINT: Discovered emails
    emails = passive.get("osint_emails", [])
    if emails:
        compiled["osint_findings"].append({
            "category": "information_disclosure",
            "title": f"Email Addresses Discovered ({len(emails)} emails)",
            "severity": "Low",
            "detail": {"emails": emails[:20]},
        })

    # Google dork hits
    dork_hits = [d for d in passive.get("google_dorks", [])
                 if isinstance(d, dict) and d.get("count", 0) > 0]
    if dork_hits:
        compiled["osint_findings"].append({
            "category": "information_disclosure",
            "title": f"Google Dork Hits Found ({len(dork_hits)} queries had results)",
            "severity": "Medium",
            "detail": {"dork_hits": dork_hits},
        })

    # Historical URLs from Wayback
    interesting_urls = passive.get("historical_urls", [])
    if interesting_urls:
        compiled["osint_findings"].append({
            "category": "information_disclosure",
            "title": f"Historical Interesting URLs Found ({len(interesting_urls)} URLs)",
            "severity": "Low",
            "detail": {"urls": interesting_urls[:20]},
        })

    # Cloud findings
    cloud = active.get("cloud_assets", {})
    for bucket in cloud.get("s3_buckets", []) + cloud.get("gcs_buckets", []):
        if isinstance(bucket, dict) and bucket.get("status") == "PUBLIC":
            compiled["infrastructure_findings"].append({
                "category": "cloud_misconfiguration",
                "title": f"Public Cloud Storage Bucket: {bucket.get('name', 'unknown')}",
                "severity": "Critical",
                "detail": bucket,
            })
    for blob in cloud.get("azure_blobs", []):
        if isinstance(blob, dict) and blob.get("status") in ["EXISTS", "PUBLIC"]:
            compiled["infrastructure_findings"].append({
                "category": "cloud_misconfiguration",
                "title": f"Azure Blob Storage Found: {blob.get('name', 'unknown')}",
                "severity": "High",
                "detail": blob,
            })

    # Dangerous HTTP methods
    for host, methods in active.get("dangerous_methods", {}).items():
        if isinstance(methods, list):
            for method in methods:
                compiled["web_findings"].append({
                    "category": "misconfiguration",
                    "host": host,
                    "title": f"Dangerous HTTP Method Enabled: {method} on {host}",
                    "severity": "High" if method in ["PUT", "DELETE", "DEBUG"] else "Medium",
                    "detail": {"host": host, "method": method},
                })

    # WAF info (informational)
    for host, waf_info in active.get("waf_info", {}).items():
        if isinstance(waf_info, dict) and not waf_info.get("detected", False):
            compiled["web_findings"].append({
                "category": "misconfiguration",
                "host": host,
                "title": f"No WAF Detected on {host}",
                "severity": "Medium",
                "detail": waf_info,
            })

    # Discovered paths
    for host, paths in active.get("discovered_paths", {}).items():
        if isinstance(paths, list) and paths:
            sensitive_paths = [p for p in paths if any(
                kw in p.lower() for kw in
                [".env", ".git", "admin", "backup", "config", "secret", "password", "db", "sql"]
            )]
            if sensitive_paths:
                compiled["web_findings"].append({
                    "category": "information_disclosure",
                    "host": host,
                    "title": f"Sensitive Paths Discovered on {host}",
                    "severity": "High",
                    "detail": {"host": host, "sensitive_paths": sensitive_paths},
                })

    # Build summary
    all_findings = (compiled["services"] + compiled["web_findings"] +
                    compiled["osint_findings"] + compiled["infrastructure_findings"])

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in all_findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    compiled["statistics"] = {
        "total_findings": len(all_findings),
        "severity_breakdown": severity_counts,
        "subdomains_count": len(compiled["infrastructure"]["subdomains"]),
        "open_ports_count": len(compiled["services"]),
        "web_findings_count": len(compiled["web_findings"]),
        "osint_findings_count": len(compiled["osint_findings"]),
        "infrastructure_findings_count": len(compiled["infrastructure_findings"]),
        "needs_cve_lookup": [
            {"host": s["host"], "service": s["service"], "version": s["version"]}
            for s in compiled["services"]
            if s.get("version") and s.get("product")
        ],
    }

    return json.dumps(compiled, ensure_ascii=False, indent=2)
