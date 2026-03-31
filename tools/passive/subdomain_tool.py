# tools/passive/subdomain_tool.py
import json
import socket
import requests
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from crewai.tools import tool

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "vpn",
    "portal", "app", "cdn", "static", "docs", "blog", "shop", "beta", "alpha",
    "internal", "corp", "remote", "git", "gitlab", "jenkins", "jira",
    "confluence", "kibana", "grafana", "prometheus", "elastic", "mongo",
    "mysql", "redis", "smtp", "pop", "imap", "webmail", "autodiscover", "owa",
    "m", "mobile", "ns1", "ns2", "mx", "mx1", "mx2", "mail2", "email",
    "webdisk", "cpanel", "whm", "plesk", "secure", "ssl", "login", "auth",
    "sso", "account", "accounts", "dashboard", "management", "manage",
    "cloud", "aws", "azure", "gcp", "s3", "assets", "media", "images",
    "download", "downloads", "files", "upload", "uploads", "support", "help",
    "forum", "community", "wiki", "intranet", "extranet", "partner",
    "partners", "clients", "client", "customer", "customers",
]


@tool("Subdomain Finder")
def subdomain_finder(domain: str) -> str:
    """
    Phát hiện subdomains bằng 2 phương pháp: Certificate Transparency (crt.sh)
    và DNS brute-force với wordlist built-in.
    Input: tên miền gốc (ví dụ: example.com)
    """
    found = {}  # key: subdomain, value: {ip, source}

    # Method 1: crt.sh Certificate Transparency
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for entry in resp.json():
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if domain in name and name != domain:
                        if name not in found:
                            found[name] = {"source": "crt.sh", "ip": None}
    except Exception:
        pass

    # Method 2: DNS brute-force
    def resolve_subdomain(word):
        sub = f"{word}.{domain}"
        try:
            answers = dns.resolver.resolve(sub, "A", lifetime=3)
            ip = str(answers[0])
            return sub, ip
        except Exception:
            return None, None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(resolve_subdomain, w): w for w in BUILTIN_WORDLIST}
        for future in as_completed(futures):
            sub, ip = future.result()
            if sub:
                if sub not in found:
                    found[sub] = {"source": "bruteforce", "ip": ip}
                elif ip:
                    found[sub]["ip"] = ip

    # Resolve IPs for crt.sh results that don't have them
    def resolve_ip(sub):
        try:
            return str(dns.resolver.resolve(sub, "A", lifetime=3)[0])
        except Exception:
            return None

    for sub, info in found.items():
        if not info.get("ip"):
            info["ip"] = resolve_ip(sub)

    result_list = [
        {"subdomain": sub, "ip": info.get("ip"), "source": info["source"]}
        for sub, info in sorted(found.items())
    ]

    return json.dumps({
        "domain": domain,
        "total_found": len(result_list),
        "subdomains": result_list,
    }, ensure_ascii=False, indent=2)
