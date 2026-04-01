# tools/passive/subdomain_tool.py
import json
import os
import random
import string
import time
import requests
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from crewai.tools import tool

BUILTIN_WORDLIST = [
    # Web / App
    "www", "www2", "www3", "web", "web2", "mobile", "m", "app", "app2", "apps",
    # Mail
    "mail", "mail2", "smtp", "smtp2", "pop", "pop3", "imap", "webmail", "email",
    "autodiscover", "owa", "exchange",
    # DNS / Network
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "mx3",
    # Access
    "vpn", "vpn2", "remote", "jump", "bastion", "fw", "firewall", "gateway",
    "proxy", "squid", "waf", "edge", "origin", "lb", "loadbalancer",
    # Dev / CI-CD
    "api", "api2", "api3", "dev", "dev2", "test", "test2", "staging", "staging2",
    "uat", "qa", "sandbox", "demo", "beta", "alpha", "preview", "lab", "labs",
    "old", "new", "v1", "v2", "v3",
    # Admin / Hosting
    "admin", "admin2", "portal", "dashboard", "panel", "cp", "cpanel", "whm",
    "plesk", "manage", "management", "console", "control", "webdisk",
    # Auth
    "sso", "auth", "login", "secure", "ssl", "account", "accounts",
    # Content / CDN
    "static", "cdn", "assets", "media", "img", "images", "files", "upload",
    "uploads", "download", "downloads", "store", "shop", "blog", "news",
    "forum", "community", "support", "help", "wiki", "docs", "documentation",
    "status", "health", "monitor", "live", "stream", "video", "meet",
    # DevOps tools
    "grafana", "kibana", "prometheus", "alertmanager", "elastic", "logstash",
    "jenkins", "gitlab", "git", "svn", "jira", "confluence", "sonar",
    "nexus", "artifactory", "registry", "vault", "consul", "zabbix", "nagios",
    # Database
    "db", "db1", "db2", "mysql", "postgres", "mongodb", "redis", "mongo",
    "memcached", "elasticsearch",
    # Internal
    "internal", "intranet", "corp", "office", "extranet", "partner", "partners",
    "vendor", "client", "clients", "customer", "customers", "backup", "cache",
    # Cloud
    "cloud", "aws", "azure", "gcp", "s3",
    # PKI / Infra
    "pki", "crl", "cert", "router", "switch",
    # Vietnamese university / organization specific
    "lms", "elearning", "sv", "sinhvien", "daa", "tuyensinh", "khtc", "qldt",
    "thuvien", "nckh", "dkmh", "tkb", "voffice", "lich", "phong", "khoa",
    "bantin", "ktx", "kytucxa", "ts", "diem", "hoclieu", "tailieu",
    "lhp", "dkht", "tkbht", "ctsv", "qhdn", "daotao", "nghiepvu",
    "kehoach", "tiepnhan", "conference", "zoom", "conf",
]


def _load_wordlist() -> list[str]:
    """Load the external wordlist file and merge with built-in entries."""
    words = set(BUILTIN_WORDLIST)
    wordlist_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "subdomains_top100.txt")
    )
    try:
        with open(wordlist_path, "r", encoding="utf-8") as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#"):
                    words.add(w)
    except OSError:
        pass
    return list(words)


def _detect_wildcard(domain: str) -> str | None:
    """Return the wildcard IP if the domain uses wildcard DNS, else None."""
    rand_sub = "".join(random.choices(string.ascii_lowercase, k=14)) + f".{domain}"
    try:
        ans = dns.resolver.resolve(rand_sub, "A", lifetime=5)
        return str(ans[0])
    except Exception:
        return None


def _crtsh_query(domain: str) -> set[str]:
    """Query crt.sh with retry on 5xx / timeout (up to 3 attempts)."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; ReconAI/1.0)"}
    for attempt in range(3):
        try:
            resp = requests.get(url, timeout=30, headers=headers)
            if resp.status_code == 200:
                names: set[str] = set()
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and domain in name and name != domain:
                            names.add(name)
                return names
            if resp.status_code < 500:
                break  # 4xx — do not retry
        except Exception:
            pass
        if attempt < 2:
            time.sleep(2 ** attempt)
    return set()


def _hackertarget_query(domain: str) -> set[str]:
    """Use HackerTarget free API to enumerate subdomains."""
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200 and "error" not in resp.text[:50].lower():
            names: set[str] = set()
            for line in resp.text.strip().splitlines():
                parts = line.split(",")
                if parts:
                    name = parts[0].strip()
                    if name and domain in name and name != domain:
                        names.add(name)
            return names
    except Exception:
        pass
    return set()


def _bufferover_query(domain: str) -> set[str]:
    """Use BufferOver DNS API to discover subdomains."""
    try:
        resp = requests.get(
            f"https://dns.bufferover.run/dns?q=.{domain}",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            names: set[str] = set()
            for entry in data.get("FDNS_A", []) + data.get("RDNS", []):
                for part in entry.split(","):
                    part = part.strip()
                    if domain in part and part != domain and not part[0].isdigit():
                        names.add(part)
            return names
    except Exception:
        pass
    return set()


def _alienvault_query(domain: str) -> set[str]:
    """Use AlienVault OTX passive DNS to enumerate subdomains."""
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            names: set[str] = set()
            for record in resp.json().get("passive_dns", []):
                hostname = record.get("hostname", "").strip()
                if hostname and domain in hostname and hostname != domain:
                    names.add(hostname)
            return names
    except Exception:
        pass
    return set()


@tool("Subdomain Finder")
def subdomain_finder(domain: str) -> str:
    """
    Phát hiện subdomains bằng nhiều phương pháp: Certificate Transparency (crt.sh),
    HackerTarget, BufferOver, AlienVault OTX, và DNS brute-force với wordlist mở rộng.
    Tự động phát hiện wildcard DNS để lọc false positives.
    Input: tên miền gốc (ví dụ: example.com)
    """
    found: dict[str, dict] = {}  # key: subdomain → {ip, source}

    # Detect wildcard DNS upfront — brute-force hits matching this IP are false positives
    wildcard_ip = _detect_wildcard(domain)

    # ── OSINT Sources (run in parallel) ─────────────────────────────────────
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_crt = pool.submit(_crtsh_query, domain)
        f_ht  = pool.submit(_hackertarget_query, domain)
        f_buf = pool.submit(_bufferover_query, domain)
        f_otx = pool.submit(_alienvault_query, domain)

        source_map = [
            (f_crt, "crt.sh"),
            (f_ht,  "hackertarget"),
            (f_buf, "bufferover"),
            (f_otx, "alienvault"),
        ]
        for fut, src in source_map:
            for sub in fut.result():
                if sub not in found:
                    found[sub] = {"source": src, "ip": None}

    # ── DNS brute-force (wildcard-aware) ─────────────────────────────────────
    wordlist = _load_wordlist()

    def resolve_subdomain(word: str):
        sub = f"{word}.{domain}"
        try:
            answers = dns.resolver.resolve(sub, "A", lifetime=5)
            ip = str(answers[0])
            if wildcard_ip and ip == wildcard_ip:
                return None, None  # False positive — wildcard
            return sub, ip
        except Exception:
            return None, None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(resolve_subdomain, w): w for w in wordlist}
        for future in as_completed(futures):
            sub, ip = future.result()
            if sub:
                if sub not in found:
                    found[sub] = {"source": "bruteforce", "ip": ip}
                elif ip:
                    found[sub]["ip"] = ip

    # ── Resolve IPs for OSINT results ────────────────────────────────────────
    def resolve_ip(sub: str) -> str | None:
        try:
            ip = str(dns.resolver.resolve(sub, "A", lifetime=5)[0])
            return ip
        except Exception:
            return None

    subs_no_ip = [s for s, info in found.items() if not info.get("ip")]
    with ThreadPoolExecutor(max_workers=20) as executor:
        ip_futures = {executor.submit(resolve_ip, s): s for s in subs_no_ip}
        for future in as_completed(ip_futures):
            sub = ip_futures[future]
            found[sub]["ip"] = future.result()

    result_list = [
        {"subdomain": sub, "ip": info.get("ip"), "source": info["source"]}
        for sub, info in sorted(found.items())
    ]

    return json.dumps({
        "domain": domain,
        "total_found": len(result_list),
        "wildcard_detected": wildcard_ip is not None,
        "wildcard_ip": wildcard_ip,
        "subdomains": result_list,
    }, ensure_ascii=False, indent=2)
