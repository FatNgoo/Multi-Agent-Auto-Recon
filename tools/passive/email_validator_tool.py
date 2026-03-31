# tools/passive/email_validator_tool.py
import json
import re
import dns.resolver
from crewai.tools import tool


@tool("Email Validator")
def email_validator(emails_input: str) -> str:
    """
    Kiểm tra tính hợp lệ của email addresses: format validation và MX record check.
    Input: chuỗi JSON chứa list emails hoặc một email đơn.
    Ví dụ: '["admin@example.com", "info@example.com"]' hoặc '"admin@example.com"'
    """
    # Parse input
    import json as _json
    try:
        data = _json.loads(emails_input)
        if isinstance(data, str):
            emails = [data]
        elif isinstance(data, list):
            emails = data
        else:
            emails = [str(data)]
    except Exception:
        # Treat as plain string
        emails = [e.strip() for e in emails_input.strip('[]"').split(",") if e.strip()]

    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    results = []

    for email in emails:
        email = email.strip().strip('"')
        entry = {
            "email": email,
            "format_valid": bool(EMAIL_REGEX.match(email)),
            "mx_valid": False,
            "mx_records": [],
            "disposable": False,
            "status": "invalid",
        }

        if entry["format_valid"]:
            domain = email.split("@")[1]
            try:
                mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
                entry["mx_valid"] = True
                entry["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_records]
                entry["status"] = "valid"
            except Exception:
                entry["mx_valid"] = False
                entry["status"] = "no_mx"

            # Simple disposable email check
            disposable_domains = {
                "mailinator.com", "10minutemail.com", "guerrillamail.com",
                "tempmail.com", "throwaway.email", "yopmail.com"
            }
            if domain.lower() in disposable_domains:
                entry["disposable"] = True
                entry["status"] = "disposable"

        results.append(entry)

    valid_count = sum(1 for r in results if r["status"] == "valid")
    return json.dumps({
        "total_checked": len(results),
        "valid_count": valid_count,
        "results": results,
    }, ensure_ascii=False, indent=2)
