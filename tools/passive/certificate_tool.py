# tools/passive/certificate_tool.py
import json
import requests
from crewai.tools import tool


@tool("Certificate Transparency Lookup")
def certificate_transparency(domain: str) -> str:
    """
    Tìm kiếm SSL certificate history từ crt.sh Certificate Transparency logs.
    Cung cấp danh sách certificates đã phát hành, issuer, SANs, ngày hết hạn.
    Input: tên miền (ví dụ: example.com)
    """
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return json.dumps({"error": f"crt.sh returned {resp.status_code}", "domain": domain})

        raw = resp.json()
        seen_ids = set()
        certs = []

        for entry in raw:
            cert_id = entry.get("id")
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)

            san_raw = entry.get("name_value", "")
            sans = [s.strip() for s in san_raw.split("\n") if s.strip()]

            certs.append({
                "cert_id": cert_id,
                "common_name": entry.get("common_name", ""),
                "issuer": entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "san": sans,
            })

        # Sort by not_before descending
        certs.sort(key=lambda x: x.get("not_before", ""), reverse=True)

        # Unique issuers
        issuers = list({c["issuer"] for c in certs if c["issuer"]})

        return json.dumps({
            "domain": domain,
            "total_certificates": len(certs),
            "unique_issuers": issuers,
            "certificates": certs[:50],  # Top 50
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
