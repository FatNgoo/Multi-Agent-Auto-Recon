# tools/passive/whois_tool.py
import json
import whois
from datetime import datetime
from crewai.tools import tool


@tool("WHOIS Domain Lookup")
def whois_lookup(domain: str) -> str:
    """
    Tra cứu thông tin đăng ký tên miền qua WHOIS protocol.
    Trả về registrar, ngày tạo, ngày hết hạn, name servers, thông tin chủ sở hữu.
    Input: tên miền (ví dụ: example.com)
    """
    try:
        w = whois.whois(domain)

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
            "domain": domain,
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

        return json.dumps(result, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
