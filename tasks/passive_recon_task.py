# tasks/passive_recon_task.py
import os
from crewai import Task
from agents.passive_recon_agent import passive_recon_agent


def create_passive_recon_task(target: str) -> Task:
    """Create the passive recon task for a given target."""
    os.makedirs("outputs/sessions", exist_ok=True)

    return Task(
        description=f"""
## NHIỆM VỤ: PASSIVE RECONNAISSANCE

**Target Domain:** {target}

Thực hiện passive reconnaissance TOÀN DIỆN cho domain trên.
Sử dụng TẤT CẢ tools có sẵn theo thứ tự sau:

### Bước 1: Domain Infrastructure
- whois_lookup("{target}") → registrar, dates, nameservers
- dns_enumeration("{target}") → A, AAAA, MX, NS, TXT, CNAME, SOA
- ip_asn_lookup("{target}") → ASN number, CIDR ranges, org name

### Bước 2: Subdomain & Certificate Discovery
- subdomain_finder("{target}") → subdomains
- certificate_transparency("{target}") → cert history từ crt.sh

### Bước 3: OSINT Intelligence
- shodan_search("{target}") → open ports, banners, CVEs
- theharvester_runner("{target}") → emails, hosts, URLs
- google_dorking("{target}") → exposed files, login pages, errors
- urlscan_passive("{target}") → passive web scan results

### Bước 4: Historical & Reverse Lookup
- wayback_machine("{target}") → archived URLs, old tech stack
- dnsdumpster_lookup("{target}") → DNS map data
- viewdns_lookup("{target}") → reverse IP, hosting history
- reverse_whois("{target}") → other domains same org

### Bước 5: Email Intelligence
- email_validator(email) cho mỗi email tìm được (nếu có)

### FORMAT OUTPUT BẮT BUỘC (JSON):
{{
    "target": "{target}",
    "scan_timestamp": "<ISO8601>",
    "whois": {{
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "name_servers": [],
        "registrant_org": "",
        "registrant_country": ""
    }},
    "dns_records": {{
        "A": [], "AAAA": [], "MX": [],
        "NS": [], "TXT": [], "CNAME": [], "SOA": "",
        "spf_record": "", "dmarc_record": ""
    }},
    "subdomains": [
        {{"subdomain": "", "ip": "", "source": "crt.sh|bruteforce"}}
    ],
    "ssl_certificates": [
        {{"common_name": "", "issuer": "", "not_after": "", "san": []}}
    ],
    "asn_info": {{
        "asn": "", "cidr": [], "org": "", "country": ""
    }},
    "shodan_data": {{
        "ip": "", "ports": [], "banners": {{}},
        "vulns": [], "hostnames": [], "os": ""
    }},
    "osint_emails": [],
    "google_dorks": [
        {{"dork": "", "count": 0, "results": []}}
    ],
    "historical_urls": [],
    "reverse_ip_domains": [],
    "related_domains": [],
    "raw_passive_notes": ""
}}

**Lưu ý:** Nếu tool không trả về data (domain private, rate limit),
ghi null vào field đó và note lại reason. KHÔNG bỏ qua fields.
""",
        expected_output=f"""JSON object hoàn chỉnh theo format trên,
với dữ liệu thực từ tất cả passive tools cho target {target}.
File được lưu tại outputs/sessions/findings_passive.json""",
        agent=passive_recon_agent,
        output_file="outputs/sessions/findings_passive.json",
    )


# Default instance (will be overridden by crew)
task_passive_recon = create_passive_recon_task("TARGET_PLACEHOLDER")
