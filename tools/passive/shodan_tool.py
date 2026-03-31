# tools/passive/shodan_tool.py
import json
import os
import socket
import shodan
from crewai.tools import tool


@tool("Shodan Search")
def shodan_search(domain_or_ip: str) -> str:
    """
    Tra cứu thông tin từ Shodan: open ports, service banners, CVEs đã biết.
    Cung cấp passive intelligence mà không cần kết nối trực tiếp target.
    Input: domain hoặc IP address
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return json.dumps({
            "status": "unavailable",
            "error": "SHODAN_API_KEY not configured",
            "input": domain_or_ip
        })

    try:
        # Resolve domain to IP if needed
        ip = domain_or_ip
        try:
            socket.inet_aton(domain_or_ip)
        except socket.error:
            ip = socket.gethostbyname(domain_or_ip)

        api = shodan.Shodan(api_key)
        host = api.host(ip)

        ports_info = []
        for item in host.get("data", []):
            ports_info.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:200],
            })

        result = {
            "input": domain_or_ip,
            "ip": ip,
            "hostnames": host.get("hostnames", []),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "vulns": list(host.get("vulns", {}).keys()) if isinstance(host.get("vulns"), dict) else list(host.get("vulns") or []),
            "tags": host.get("tags", []),
            "org": host.get("org"),
            "isp": host.get("isp"),
            "country_code": host.get("country_code"),
            "last_update": host.get("last_update"),
            "services": ports_info,
        }
        return json.dumps(result, ensure_ascii=False, indent=2)

    except shodan.exception.APIError as e:
        return json.dumps({"status": "not_found", "error": str(e), "input": domain_or_ip})
    except Exception as e:
        return json.dumps({"error": str(e), "input": domain_or_ip})
