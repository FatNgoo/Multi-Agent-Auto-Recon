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

### Bước 6: LƯU KẾT QUẢ (BẮT BUỘC - BƯỚC CUỐI)
Gọi finalize_passive_findings với compact JSON chứa các fields NHỎ sau
(KHÔNG include subdomains hay historical_urls — đã được lưu tự động bởi tools):

finalize_passive_findings('{{"target": "{target}", "scan_timestamp": "<ISO8601>",
  "whois": {{"registrar": "", "creation_date": "", "expiration_date": "",
    "name_servers": [], "registrant_org": "", "registrant_country": ""}},
  "dns_records": {{"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
    "CNAME": [], "SOA": "", "spf_record": "", "dmarc_record": "",
    "security_notes": []}},
  "ssl_certificates": [{{"common_name": "", "issuer": "", "not_after": "", "san": []}}],
  "asn_info": {{"asn": "", "cidr": [], "org": "", "country": ""}},
  "shodan_data": {{"ip": "", "ports": [], "banners": {{}}, "vulns": [], "hostnames": [], "os": ""}},
  "osint_emails": [],
  "google_dorks": [{{"dork": "", "count": 0, "results": []}}],
  "reverse_ip_domains": [],
  "related_domains": [],
  "raw_passive_notes": ""
}}')

**QUAN TRỌNG:**
- CHỈ điền vào các fields trên bằng dữ liệu thực từ tool outputs
- KHÔNG include "subdomains" (tự động từ subdomain_finder cache)
- KHÔNG include "historical_urls" (tự động từ wayback cache)
- Nếu field không có data, để null hoặc []
""",
        expected_output=f"""Xác nhận đã gọi finalize_passive_findings thành công cho {target}.
File đã được lưu tại outputs/sessions/findings_passive.json""",
        agent=passive_recon_agent,
    )


# Default instance (will be overridden by crew)
task_passive_recon = create_passive_recon_task("TARGET_PLACEHOLDER")
