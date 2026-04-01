# tools/passive/whois_tool.py
import json
import whois
from datetime import datetime
from crewai.tools import tool


def _extract_root_domain(domain: str) -> str:
    """
    Extract the registrable root domain (eTLD+1) from a potentially
    multi-level subdomain.  E.g.: scanme.nmap.org → nmap.org
    This prevents WHOIS lookup failures for subdomains whose registry
    record only exists at the root level.
    """
    # Strip protocol prefix if accidentally included
    domain = domain.strip().lower()
    for prefix in ("http://", "https://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]  # remove path

    parts = domain.split(".")
    # Known two-part TLDs (co.uk, com.au, org.nz, …)
    two_part_tlds = {
        "co.uk", "com.au", "org.uk", "net.au", "org.au",
        "com.br", "net.br", "org.br", "co.nz", "org.nz",
        "co.jp", "or.jp", "ne.jp", "co.za", "org.za",
    }
    if len(parts) >= 3:
        candidate_tld = ".".join(parts[-2:])
        if candidate_tld in two_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


@tool("WHOIS Domain Lookup")
def whois_lookup(domain: str) -> str:
    """
    Tra cứu thông tin đăng ký tên miền qua WHOIS protocol.
    Tự động normalize về root domain (eTLD+1) nếu input là subdomain.
    Trả về registrar, ngày tạo, ngày hết hạn, name servers, thông tin chủ sở hữu.
    Input: tên miền (ví dụ: scanme.nmap.org → sẽ tự tra nmap.org)
    """
    # Always look up the root domain for WHOIS — subdomain WHOIS always fails
    root_domain = _extract_root_domain(domain)

    def _do_whois(d: str) -> dict:
        w = whois.whois(d)

        def safe_str(val):
            if val is None:
                return None
            if isinstance(val, list):
                return [str(v) for v in val]
            if isinstance(val, datetime):
                return val.isoformat()
            return str(val)

        creation = w.creation_date
        expiration = w.expiration_date
        updated = w.updated_date

        result = {
            "domain": d,
            "queried_domain": d,
            "original_input": domain,
            "registrar": safe_str(w.registrar),
            "creation_date": safe_str(creation[0] if isinstance(creation, list) else creation),
            "expiration_date": safe_str(expiration[0] if isinstance(expiration, list) else expiration),
            "updated_date": safe_str(updated[0] if isinstance(updated, list) else updated),
            "name_servers": [ns.lower() for ns in (w.name_servers or [])],
            "registrant_org": safe_str(w.org),
            "registrant_country": safe_str(w.country),
            "registrant_email": safe_str(w.emails),
            "status": safe_str(w.status),
            "dnssec": safe_str(w.dnssec),
        }

        # Calculate days until expiry
        if result["expiration_date"]:
            try:
                exp = datetime.fromisoformat(result["expiration_date"])
                days_left = (exp - datetime.now()).days
                result["days_until_expiry"] = days_left
                if days_left < 30:
                    result["expiry_warning"] = f"Domain expires in {days_left} days!"
            except Exception:
                pass
        return result

    try:
        result = _do_whois(root_domain)
        if root_domain != domain:
            result["note"] = (
                f"WHOIS performed on root domain '{root_domain}' "
                f"(original input '{domain}' is a subdomain)."
            )
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        # If root domain lookup failed too, return structured error
        return json.dumps({
            "error": str(e),
            "domain": domain,
            "queried_domain": root_domain,
            "note": "WHOIS lookup failed. Domain may use privacy protection or registry restricts queries.",
        })
