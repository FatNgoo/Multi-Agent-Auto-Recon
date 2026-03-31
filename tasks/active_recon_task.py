# tasks/active_recon_task.py
import os
from crewai import Task
from agents.active_recon_agent import active_recon_agent


def create_active_recon_task(target: str, passive_task: Task) -> Task:
    """Create the active recon task for a given target."""
    os.makedirs("outputs/sessions", exist_ok=True)

    return Task(
        description=f"""
## NHIỆM VỤ: ACTIVE RECONNAISSANCE

**Target:** {target}

**QUAN TRỌNG:**
- Đọc kỹ passive findings từ context trước khi bắt đầu scan!
- Thử kết nối HTTP trước (http://), nếu thành công thì dùng HTTP.
  Chỉ dùng HTTPS nếu port 443 mở. KHÔNG mặc định dùng https://.

### Bước 1: Network Scanning
Lấy IPs từ passive findings (dns_records.A + asn_info.cidr):
- masscan_wrapper({{"hosts": "{target}", "ports": "80,443,22,21,25,53,110,143,8080,8443,3000,5000,8000,9000"}})
- nmap_port_scan({{"host": "{target}", "ports": "80,443,22,21,25,53,110,143,8080,8443", "scan_type": "version"}})

### Bước 2: Per-Host Analysis
- banner_grabber({{"host": "{target}", "ports": [80, 443, 22]}})
- waf_detector("http://{target}")
- whatweb_fingerprint("http://{target}")
- technology_stack_analyzer("http://{target}")

### Bước 3: Web Security Assessment
- ssl_tls_checker("{target}")
- http_security_headers("http://{target}")
- robots_sitemap_parser("http://{target}")
- favicon_hasher("http://{target}")

### Bước 4: Content Discovery
- url_crawler({{"url": "http://{target}", "depth": 2}})
- directory_enumerator({{"url": "http://{target}", "wordlist_size": "small"}})
- param_discoverer({{"url": "http://{target}"}})

### Bước 5: Infrastructure Check
- cloud_asset_finder("{target}")
- http_method_checker("http://{target}")

### FORMAT OUTPUT BẮT BUỘC (JSON):
{{
    "target": "{target}",
    "scan_timestamp": "<ISO8601>",
    "hosts_scanned": [],
    "open_ports": {{
        "<host_ip>": {{
            "<port>": {{
                "state": "open",
                "protocol": "tcp",
                "service": "http",
                "version": "nginx 1.18.0",
                "banner": ""
            }}
        }}
    }},
    "web_technologies": {{
        "{target}": {{
            "cms": "", "server": "", "framework": "",
            "language": "", "cdn": "", "analytics": [],
            "libraries": []
        }}
    }},
    "ssl_findings": [
        {{
            "host": "", "issue": "",
            "tls_versions": [], "weak_ciphers": [],
            "cert_expiry_days": 0, "cert_cn": ""
        }}
    ],
    "missing_headers": {{
        "{target}": ["header1", "header2"]
    }},
    "waf_info": {{
        "{target}": {{"detected": false, "product": null}}
    }},
    "discovered_paths": {{
        "{target}": ["/admin", "/backup"]
    }},
    "discovered_params": {{
        "https://{target}": ["id", "user"]
    }},
    "cloud_assets": {{
        "s3_buckets": [], "azure_blobs": [], "gcs_buckets": []
    }},
    "dangerous_methods": {{
        "{target}": []
    }},
    "robots_txt_paths": {{
        "{target}": {{"disallowed": [], "allowed": [], "sitemaps": []}}
    }},
    "favicon_hash": {{
        "{target}": {{"hash": null, "shodan_query": ""}}
    }},
    "all_urls": [],
    "raw_active_notes": ""
}}
""",
        expected_output=f"""JSON object đầy đủ theo format trên với
tất cả active scan results cho target {target}.
File lưu tại outputs/sessions/findings_active.json""",
        agent=active_recon_agent,
        context=[passive_task],
        output_file="outputs/sessions/findings_active.json",
    )


def create_active_recon_task_simple(target: str) -> Task:
    """Create active recon task without context dependency."""
    os.makedirs("outputs/sessions", exist_ok=True)

    return Task(
        description=f"""
## ACTIVE RECON for {target}

Thực hiện active recon cho target {target}:
1. nmap_port_scan với target {target}, ports 80,443,22,21
2. ssl_tls_checker cho {target}
3. http_security_headers cho https://{target}
4. waf_detector cho https://{target}
5. whatweb_fingerprint cho https://{target}
6. robots_sitemap_parser cho https://{target}
7. directory_enumerator với small wordlist
8. cloud_asset_finder cho {target}
9. http_method_checker cho https://{target}

Output: JSON với open_ports, ssl_findings, missing_headers, waf_info, discovered_paths
""",
        expected_output="JSON object với active scan results",
        agent=active_recon_agent,
        output_file="outputs/sessions/findings_active.json",
    )


# Default instance
task_active_recon = create_active_recon_task_simple("TARGET_PLACEHOLDER")
