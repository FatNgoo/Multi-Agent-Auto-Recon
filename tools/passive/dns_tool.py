# tools/passive/dns_tool.py
import json
import dns.resolver
import dns.exception
from crewai.tools import tool


@tool("DNS Enumeration")
def dns_enumeration(domain: str) -> str:
    """
    Thực hiện DNS enumeration toàn diện cho domain.
    Lấy các record types: A, AAAA, MX, NS, TXT, CNAME, SOA.
    Phân tích SPF và DMARC records để đánh giá email security.
    Input: tên miền (ví dụ: example.com)
    """
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {}
    security_notes = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            if rtype == "MX":
                results[rtype] = sorted(
                    [{"priority": r.preference, "exchange": str(r.exchange).rstrip(".")}
                     for r in answers],
                    key=lambda x: x["priority"]
                )
            elif rtype == "SOA":
                r = answers[0]
                results[rtype] = {
                    "mname": str(r.mname).rstrip("."),
                    "rname": str(r.rname).rstrip("."),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum,
                }
            else:
                results[rtype] = [str(r).rstrip(".") for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            results[rtype] = []
        except dns.exception.DNSException as e:
            results[rtype] = []
            security_notes.append(f"{rtype} lookup error: {str(e)}")

    # Analyze TXT records for SPF / DMARC
    spf = None
    dmarc = None
    for txt in results.get("TXT", []):
        if txt.startswith("v=spf1"):
            spf = txt
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = str(dmarc_answers[0]).strip('"')
    except Exception:
        pass

    results["spf_record"] = spf
    results["dmarc_record"] = dmarc

    # Security notes
    if not spf:
        security_notes.append("No SPF record found - email spoofing risk")
    if not dmarc:
        security_notes.append("No DMARC record found - phishing risk")
    if not results.get("AAAA"):
        security_notes.append("No IPv6 (AAAA) records found")

    results["security_notes"] = security_notes

    return json.dumps(results, ensure_ascii=False, indent=2)
