# tools/active/ssl_tool.py
import json
import ssl
import socket
import datetime
from crewai.tools import tool

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@tool("SSL/TLS Security Checker")
def ssl_tls_checker(host: str) -> str:
    """
    Kiểm tra SSL/TLS configuration: TLS version, cipher suites, certificate validity.
    Phát hiện weak ciphers, expired certs, self-signed certs, TLS downgrade risks.
    Input: hostname (ví dụ: example.com)
    """
    host = host.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
    port = 443

    issues = []
    result = {
        "host": host,
        "port": port,
        "reachable": False,
        "tls_version": None,
        "cipher_suite": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_expiry_days": None,
        "san_domains": [],
        "self_signed": False,
        "wildcard_cert": False,
        "issues": [],
        "grade": "Unknown",
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result["reachable"] = True
                result["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                result["cipher_suite"] = cipher[0] if cipher else None

                # Get certificate info
                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["cert_subject"] = subject.get("commonName", "")
                    result["cert_issuer"] = issuer.get("organizationName", "")

                    # Check expiry
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        result["cert_expiry"] = expiry.isoformat()
                        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                        days_left = (expiry - now_utc).days
                        result["cert_expiry_days"] = days_left
                        if days_left < 0:
                            issues.append({"type": "expired_cert", "severity": "Critical",
                                           "detail": "Certificate has expired"})
                        elif days_left < 30:
                            issues.append({"type": "expiring_soon", "severity": "High",
                                           "detail": f"Certificate expires in {days_left} days"})

                    # SANs
                    sans = [v for _, v in cert.get("subjectAltName", [])]
                    result["san_domains"] = sans

                    # Self-signed check
                    if subject == issuer:
                        result["self_signed"] = True
                        issues.append({"type": "self_signed", "severity": "Medium",
                                       "detail": "Self-signed certificate detected"})

                    # Wildcard check
                    cn = result["cert_subject"] or ""
                    if cn.startswith("*."):
                        result["wildcard_cert"] = True

                # TLS version issues
                tls = result["tls_version"]
                if tls in ("TLSv1", "TLSv1.1"):
                    issues.append({"type": "outdated_tls", "severity": "High",
                                   "detail": f"{tls} is deprecated and insecure"})
                elif tls == "SSLv3":
                    issues.append({"type": "sslv3", "severity": "Critical",
                                   "detail": "SSLv3 is vulnerable to POODLE attack"})

                # Weak cipher check
                if cipher:
                    cipher_name = cipher[0].upper()
                    for weak in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]:
                        if weak in cipher_name:
                            issues.append({"type": "weak_cipher", "severity": "High",
                                           "detail": f"Weak cipher: {cipher[0]}"})
                            break

    except ssl.SSLError as e:
        issues.append({"type": "ssl_error", "severity": "High", "detail": str(e)})
        result["reachable"] = True
    except (ConnectionRefusedError, socket.timeout, OSError):
        result["reachable"] = False
        return json.dumps(result, ensure_ascii=False, indent=2)

    result["issues"] = issues

    # Grade calculation
    if not issues:
        result["grade"] = "A"
    elif any(i["severity"] == "Critical" for i in issues):
        result["grade"] = "F"
    elif any(i["severity"] == "High" for i in issues):
        result["grade"] = "C"
    elif any(i["severity"] == "Medium" for i in issues):
        result["grade"] = "B"
    else:
        result["grade"] = "B+"

    return json.dumps(result, ensure_ascii=False, indent=2)
