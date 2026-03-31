# tools/passive/ip_asn_tool.py
import json
import socket
import requests
from ipwhois import IPWhois
from crewai.tools import tool


@tool("IP and ASN Lookup")
def ip_asn_lookup(domain_or_ip: str) -> str:
    """
    Tìm thông tin ASN (Autonomous System Number), CIDR ranges, và tổ chức
    sở hữu IP của target. Xác định toàn bộ IP ranges của một tổ chức.
    Input: domain hoặc IP address
    """
    try:
        # Resolve domain to IP if needed
        ip = domain_or_ip
        try:
            socket.inet_aton(domain_or_ip)
        except socket.error:
            ip = socket.gethostbyname(domain_or_ip)

        obj = IPWhois(ip)
        result_raw = obj.lookup_rdap(depth=1)

        asn_data = {
            "queried_input": domain_or_ip,
            "resolved_ip": ip,
            "asn": result_raw.get("asn"),
            "asn_description": result_raw.get("asn_description"),
            "asn_country_code": result_raw.get("asn_country_code"),
            "asn_cidr": result_raw.get("asn_cidr"),
            "network_name": result_raw.get("network", {}).get("name"),
            "network_cidr": result_raw.get("network", {}).get("cidr"),
        }

        # BGPView API for additional prefixes
        try:
            bgp_url = f"https://api.bgpview.io/ip/{ip}"
            resp = requests.get(bgp_url, timeout=10)
            if resp.status_code == 200:
                bgp_data = resp.json().get("data", {})
                prefixes = bgp_data.get("prefixes", [])
                asn_data["bgp_prefixes"] = [p.get("prefix") for p in prefixes[:10]]
                if bgp_data.get("rir_allocation"):
                    asn_data["rir"] = bgp_data["rir_allocation"].get("rir_name")
        except Exception:
            pass

        return json.dumps(asn_data, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "input": domain_or_ip})
