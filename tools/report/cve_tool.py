# tools/report/cve_tool.py
import json
import time
import os
import requests
from crewai.tools import tool


@tool("CVE Lookup")
def cve_lookup(input_json: str) -> str:
    """
    Tra cứu CVE từ NVD (National Vulnerability Database) dựa trên tên và phiên bản dịch vụ.
    Input: JSON string {"service": "nginx", "version": "1.18.0"}
    hoặc string đơn giản như "nginx 1.18.0"
    """
    try:
        try:
            params = json.loads(input_json)
            service = params.get("service", "")
            version = params.get("version", "")
        except Exception:
            # Plain string like "nginx 1.18.0"
            parts = input_json.strip().split(None, 1)
            service = parts[0] if parts else ""
            version = parts[1] if len(parts) > 1 else ""

        if not service:
            return json.dumps({"error": "No service name provided"})

        query = f"{service} {version}".strip()
        api_key = os.getenv("NVD_API_KEY")

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        params_req = {
            "keywordSearch": query,
            "resultsPerPage": 5,
            "startIndex": 0,
        }

        # Rate limit: without API key, NVD requires 6s delay
        if not api_key:
            time.sleep(6)

        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params_req,
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 403:
            return json.dumps({
                "query": query,
                "error": "NVD API rate limited or forbidden",
                "suggestion": "Add NVD_API_KEY to .env for better rate limits",
                "cves": [],
            })

        if resp.status_code != 200:
            return json.dumps({
                "query": query,
                "error": f"NVD API returned status {resp.status_code}",
                "cves": [],
            })

        raw = resp.json()
        vulnerabilities = raw.get("vulnerabilities", [])

        cves = []
        for vuln in vulnerabilities:
            cve_obj = vuln.get("cve", {})
            cve_id = cve_obj.get("id", "")
            descriptions = cve_obj.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )

            # CVSS v3 score
            cvss_v3_score = None
            cvss_v3_vector = None
            severity = "Unknown"

            metrics = cve_obj.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2 = metrics.get("cvssMetricV2", [])

            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
                severity = cvss_data.get("baseSeverity", "Unknown")
            elif cvss_v30:
                cvss_data = cvss_v30[0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
                severity = cvss_data.get("baseSeverity", "Unknown")
            elif cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                severity = cvss_v2[0].get("baseSeverity", "Unknown")

            # Skip very low scores
            if cvss_v3_score is not None and cvss_v3_score < 4.0:
                continue

            # CWE
            weaknesses = cve_obj.get("weaknesses", [])
            cwes = []
            for w in weaknesses:
                for desc in w.get("description", []):
                    cwes.append(desc.get("value", ""))

            # References
            refs = cve_obj.get("references", [])
            ref_urls = [r.get("url") for r in refs[:3]]

            cves.append({
                "cve_id": cve_id,
                "description": description[:300],
                "cvss_v3_score": cvss_v3_score,
                "cvss_v3_vector": cvss_v3_vector,
                "severity": severity,
                "published": cve_obj.get("published", ""),
                "last_modified": cve_obj.get("lastModified", ""),
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cwe": cwes,
                "references": ref_urls,
            })

        # Sort by CVSS score descending
        cves.sort(key=lambda x: x.get("cvss_v3_score") or 0, reverse=True)

        return json.dumps({
            "query": query,
            "total_found": raw.get("totalResults", 0),
            "returned": len(cves),
            "cves": cves,
        }, ensure_ascii=False, indent=2)

    except requests.exceptions.Timeout:
        return json.dumps({"error": "NVD API timeout", "query": input_json, "cves": []})
    except Exception as e:
        return json.dumps({"error": str(e), "query": input_json, "cves": []})
