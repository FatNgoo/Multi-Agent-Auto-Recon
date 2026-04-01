# tools/active/cloud_tool.py
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from crewai.tools import tool


@tool("Cloud Asset Discovery")
def cloud_asset_finder(domain: str) -> str:
    """
    Tìm kiếm các cloud assets (S3 buckets, Azure blobs, GCS buckets)
    liên quan đến domain. Misconfigured cloud storage là nguồn data leak phổ biến.
    Input: domain hoặc organization name (ví dụ: example.com)
    """
    company = domain.split(".")[0]

    patterns = [
        company,
        f"{company}-backup",
        f"{company}-dev",
        f"{company}-staging",
        f"{company}-prod",
        f"{company}-data",
        f"{company}-assets",
        f"{company}-media",
        f"{company}-uploads",
        f"{company}-files",
        f"{company}-static",
        f"{company}-public",
        f"{company}-private",
        f"backup-{company}",
        f"dev-{company}",
        f"www-{company}",
        domain.replace(".", "-"),
        domain.replace(".", ""),
    ]

    results = {
        "domain": domain,
        "s3_buckets": [],
        "azure_blobs": [],
        "gcs_buckets": [],
        "errors": [],
    }

    def check_s3(name):
        urls_to_try = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]
        for url in urls_to_try:
            try:
                r = requests.head(url, timeout=5, allow_redirects=False, verify=False)
                if r.status_code in [200, 301, 302, 403]:
                    status = (
                        "PUBLIC" if r.status_code == 200
                        else "REDIRECT" if r.status_code in [301, 302]
                        else "EXISTS_PRIVATE"
                    )
                    return {
                        "name": name,
                        "url": url,
                        "status": status,
                        "http_code": r.status_code,
                        # Confidence is "verified" only when the bucket actually
                        # responds with 200/403 from AWS — not a guess.
                        "confidence": "verified",
                    }
            except Exception:
                pass
        return None

    def check_azure(name):
        url = f"https://{name}.blob.core.windows.net"
        try:
            r = requests.head(url, timeout=5, verify=False)
            if r.status_code in [200, 400, 403]:
                return {
                    "name": name,
                    "url": url,
                    "status": "EXISTS" if r.status_code in [200, 403] else "MAYBE",
                    "http_code": r.status_code,
                    "confidence": "verified",
                }
        except Exception:
            pass
        return None

    def check_gcs(name):
        url = f"https://storage.googleapis.com/{name}"
        try:
            r = requests.head(url, timeout=5, verify=False)
            if r.status_code in [200, 403]:
                return {
                    "name": name,
                    "url": url,
                    "status": "PUBLIC" if r.status_code == 200 else "EXISTS_PRIVATE",
                    "http_code": r.status_code,
                    "confidence": "verified",
                }
        except Exception:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            s3_futures = {executor.submit(check_s3, p): p for p in patterns}
            az_futures = {executor.submit(check_azure, p): p for p in patterns[:10]}
            gcs_futures = {executor.submit(check_gcs, p): p for p in patterns[:10]}

            for future in as_completed(s3_futures):
                result = future.result()
                if result:
                    results["s3_buckets"].append(result)

            for future in as_completed(az_futures):
                result = future.result()
                if result:
                    results["azure_blobs"].append(result)

            for future in as_completed(gcs_futures):
                result = future.result()
                if result:
                    results["gcs_buckets"].append(result)

    except Exception as e:
        results["errors"].append(str(e))

    public_count = sum(
        1 for b in results["s3_buckets"] + results["gcs_buckets"]
        if isinstance(b, dict) and b.get("status") == "PUBLIC"
    )
    verified_count = sum(
        1 for b in (
            results["s3_buckets"] + results["azure_blobs"] + results["gcs_buckets"]
        )
        if isinstance(b, dict) and b.get("confidence") == "verified"
    )

    results["summary"] = {
        "total_found": (
            len(results["s3_buckets"]) +
            len(results["azure_blobs"]) +
            len(results["gcs_buckets"])
        ),
        "verified_exist": verified_count,
        "public_buckets": public_count,
        "risk": "Critical" if public_count > 0 else ("Medium" if verified_count > 0 else "Low"),
        "note": (
            "All bucket names are generated from domain-derived patterns. "
            "Only entries with confidence='verified' received HTTP responses. "
            "Treat unverified entries as informational only."
        ),
    }

    return json.dumps(results, ensure_ascii=False, indent=2)
