# tools/report/report_gen_tool.py
import json
import os
from datetime import datetime
from openai import OpenAI
from crewai.tools import tool


REPORT_SYSTEM_PROMPT = """Bạn là Principal Security Consultant với 15 năm kinh nghiệm viết pentest reports.
Chuẩn báo cáo: PTES (Penetration Testing Execution Standard), OWASP Testing Guide v4, CVSS v3.1.
Ngôn ngữ: Tiếng Việt (technical terms giữ tiếng Anh).
Format: Markdown hoàn chỉnh, đầy đủ tiêu đề, bảng, và nội dung chi tiết.

QUY TẮC EVIDENCE BẮT BUỘC:
1. Chỉ viết những gì có evidence từ data. KHÔNG fabricate findings hoặc phóng đại.
2. LUÔN phân biệt rõ nguồn dữ liệu:
   - "Active-confirmed" (source="active_confirmed"): port/service đã được nmap scan trực tiếp xác nhận
   - "Passive/Shodan-observed" (shodan_observed_ports): port từ Shodan API, CHƯA được active scan xác nhận
   - KHÔNG được gộp hai nguồn này thành "X open ports" mà không ghi rõ nguồn
3. Cloud assets với confidence="heuristic" hoặc source="heuristic_guess": chỉ là suy đoán từ tên domain,
   KHÔNG xem là finding thật, chỉ ghi là "potential/unverified"
4. CMS/Tech stack: chỉ báo cáo nếu CMS không null và có signals. Ghi "(detected)" hay "(undetected)" rõ ràng.
5. CVE: chỉ đề cập khi có service version cụ thể. Không dùng cụm "100+ CVEs" chung chung.
6. Risk score: tính từ findings thật, không inflate."""


@tool("Attack Surface Report Generator")
def report_generator(input_json: str) -> str:
    """
    Tạo báo cáo Attack Surface Assessment hoàn chỉnh bằng DeepSeek AI.
    Báo cáo bao gồm Executive Summary, Findings, Risk Matrix, Recommendations.
    Input: JSON string chứa tất cả findings đã compiled và risk score.
    """
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        return _generate_fallback_report(input_json)

    try:
        data = json.loads(input_json)
    except Exception:
        data = {"raw": input_json}

    # The LLM agent sometimes wraps compiled findings inside a key like
    # "compiled_findings".  Unwrap it so that the rest of the code can
    # access top-level keys (meta, services, statistics, …) consistently.
    if "compiled_findings" in data and isinstance(data["compiled_findings"], dict):
        outer = data
        data = data["compiled_findings"]
        # Pull risk score / cve data from the outer wrapper if not in compiled
        if "overall_risk_score" not in data:
            data["overall_risk_score"] = (
                outer.get("overall_risk_score") or outer.get("risk_score")
            )
        if "risk_level" not in data:
            data["risk_level"] = outer.get("risk_level")
        if "cves" not in data:
            data["cves"] = outer.get("cves", [])

    target = (data.get("meta", {}).get("target") or
              data.get("target", "Unknown Target"))

    # Prepare summary for LLM (trim to avoid token overflow)
    stats = data.get("statistics", {})
    sev = stats.get("severity_breakdown", {})

    services = data.get("services", [])
    web_findings = data.get("web_findings", [])
    osint_findings = data.get("osint_findings", [])
    infra_findings = data.get("infrastructure_findings", [])

    # Active-confirmed ports only (source="active_confirmed")
    active_confirmed_services = [s for s in services if s.get("source") == "active_confirmed"]
    # Shodan-observed ports (passive intelligence)
    shodan_ports = data.get("infrastructure", {}).get("shodan_observed_ports", [])

    # Top findings for report — exclude heuristic cloud entries from Critical count
    all_findings = (
        [f for f in infra_findings if f.get("severity") == "Critical"
         and f.get("source") != "heuristic_guess"] +
        [f for f in web_findings + services if f.get("severity") in ["Critical", "High"]] +
        [f for f in web_findings + services if f.get("severity") == "Medium"]
    )[:15]

    # Service versions for CVE context
    versioned_services = [
        s for s in services if s.get("version")
    ][:10]

    summary_for_llm = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "statistics": {
            "total_findings": stats.get("total_findings", len(all_findings)),
            "severity": sev,
            "subdomains_found": stats.get("subdomains_count", 0),
            # Only active-confirmed ports in the primary count
            "active_confirmed_ports": len(active_confirmed_services),
            # Shodan-observed ports are passive intelligence
            "shodan_observed_ports": shodan_ports,
        },
        "infrastructure": data.get("infrastructure", {}),
        "active_confirmed_services": active_confirmed_services,
        "key_findings": all_findings,
        "versioned_services": versioned_services,
        "risk_score": data.get("overall_risk_score"),
        "risk_level": data.get("risk_level"),
    }

    # Count active-confirmed ports for display
    active_port_count = len(active_confirmed_services)
    shodan_port_count = len(shodan_ports)

    user_prompt = f"""
<analysis>
**Bước 1 — Đánh giá tổng quan target:**
- Target: {target}
- Subdomains: {stats.get("subdomains_count", 0)}
- Active-confirmed ports (nmap scan): {active_port_count}
- Shodan-observed ports (passive, NOT yet active-confirmed): {shodan_port_count}
- Risk score: {data.get("overall_risk_score", "N/A")}/100

**Bước 2 — Top rủi ro từ findings (chỉ từ evidence thật):**
Critical: {sev.get("Critical", 0)}, High: {sev.get("High", 0)}, Medium: {sev.get("Medium", 0)}

**Bước 3 — Business impact analysis:**
Đánh giá khả năng khai thác và tác động kinh doanh của các findings có evidence cụ thể.

QUY TẮC QUAN TRỌNG:
- Khi đề cập ports, phân biệt: "X ports confirmed by active scan" vs "Y ports observed by Shodan (passive)"
- Cloud buckets có source=heuristic_guess → chỉ liệt kê phần Appendix, KHÔNG đưa vào findings chính
- KHÔNG dùng cụm "100+ CVEs" trừ khi data cung cấp CVE IDs cụ thể
</analysis>

Bây giờ viết báo cáo đầy đủ với format Markdown:

# ATTACK SURFACE ASSESSMENT REPORT
## Target: {target}
## Date: {datetime.now().strftime("%Y-%m-%d")}

## 1. Executive Summary
[200-300 từ tiếng Việt - không dùng technical jargon - mô tả rủi ro và business impact]

## 2. Scope & Methodology
[Mô tả target, tools sử dụng, approach, limitations]

## 3. Attack Surface Overview
[Tổng quan infrastructure: domains, IPs, services, entry points.
Ghi rõ: "Active scan confirmed X ports. Shodan observed Y additional ports (passive intelligence)."]

## 4. Findings Summary

| ID | Severity | Category | Title | Evidence Source | CVSS Score |
|---|---|---|---|---|---|
[Liệt kê tất cả findings từ data, ghi rõ evidence source]

## 5. Detailed Technical Findings
[Với mỗi finding quan trọng (Critical/High/Medium):
### FIND-XXX — Title
**Severity:** | **CVSS:** | **Category:**
**Description:** [kỹ thuật]
**Evidence:** [nguồn + raw data]
**Impact:** [business + technical]
**Recommendation:** [steps cụ thể]
**References:** [CVE/OWASP links nếu có]
]

## 6. Risk Matrix

| Likelihood / Impact | Critical | High | Medium | Low |
|---|---|---|---|---|
| High | | | | |
| Medium | | | | |
| Low | | | | |

## 7. Remediation Roadmap

### Immediate (0-7 ngày)
[Critical findings]

### Short-term (7-30 ngày)  
[High findings]

### Long-term (30-90 ngày)
[Medium/Low findings]

## 8. Appendix

### Tools Used
[Liệt kê tools passive + active]

### Scan Statistics
[Raw numbers từ data]

DATA:
{json.dumps(summary_for_llm, ensure_ascii=False, indent=2)[:5000]}
"""

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com",
    )

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=8000,
            temperature=0.3,
        )

        report_md = response.choices[0].message.content

        # Save to file
        os.makedirs("outputs/reports", exist_ok=True)
        report_path = "outputs/reports/attack_surface_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        # Return a compact status (not the full markdown) so the LLM does NOT
        # try to inline the large markdown string when calling export_report.
        # The LLM should call: export_report({"report_path": "outputs/reports/attack_surface_report.md"})
        return json.dumps({
            "status": "success",
            "report_path": report_path,
            "report_length_chars": len(report_md),
            "preview": report_md[:300],
            "instruction": (
                "Report saved. Call export_report with "
                '{\"report_path\": \"outputs/reports/attack_surface_report.md\"} '
                "to generate HTML and PDF."
            ),
        }, ensure_ascii=False)

    except Exception as e:
        fallback = _generate_fallback_report(input_json)
        return fallback


def _generate_fallback_report(input_json: str) -> str:
    """Generate a basic report without AI when API is unavailable."""
    try:
        data = json.loads(input_json)
    except Exception:
        data = {}

    target = data.get("meta", {}).get("target", data.get("target", "Unknown"))
    stats = data.get("statistics", {})
    sev = stats.get("severity_breakdown", {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    services = data.get("services", [])
    web_findings = data.get("web_findings", [])
    infra_findings = data.get("infrastructure_findings", [])
    all_findings = services + web_findings + infra_findings

    findings_table = "| ID | Severity | Title |\n|---|---|---|\n"
    for i, f in enumerate(all_findings[:20], 1):
        title = f.get("title", f.get("service", "Unknown"))[:60]
        sev_val = f.get("severity", "Info")
        findings_table += f"| FIND-{i:03d} | {sev_val} | {title} |\n"

    report = f"""# ATTACK SURFACE ASSESSMENT REPORT

**Target:** {target}  
**Date:** {now}  
**Status:** Auto-generated (API not available)

---

## 1. Executive Summary

Báo cáo này tổng hợp kết quả quét bảo mật tự động cho domain **{target}**.
Quá trình bao gồm passive reconnaissance (OSINT, DNS, subdomains) và active reconnaissance 
(port scanning, web fingerprinting, SSL/TLS checks).

**Tổng số findings:** {stats.get("total_findings", len(all_findings))}  
**Critical:** {sev.get("Critical", 0)} | **High:** {sev.get("High", 0)} | **Medium:** {sev.get("Medium", 0)} | **Low:** {sev.get("Low", 0)}

---

## 2. Scope & Methodology

**Target Domain:** {target}  
**Methodology:** PTES (Penetration Testing Execution Standard)  
**Tools:** Nmap, python-whois, dnspython, shodan, ssl, requests, BeautifulSoup

---

## 3. Attack Surface Overview

**Subdomains Discovered:** {stats.get("subdomains_count", 0)}  
**Open Ports:** {stats.get("open_ports_count", 0)}  
**Web Findings:** {stats.get("web_findings_count", 0)}  
**Infrastructure Findings:** {stats.get("infrastructure_findings_count", 0)}

---

## 4. Findings Summary

{findings_table}

---

## 5. Recommendations

- Ưu tiên khắc phục ngay các findings Critical và High
- Kiểm tra lại cấu hình SSL/TLS và security headers
- Vá lỗi các service có phiên bản outdated

---

## 6. Appendix

Báo cáo được tạo tự động bởi Multi-Agent Recon System.
"""

    os.makedirs("outputs/reports", exist_ok=True)
    with open("outputs/reports/attack_surface_report.md", "w", encoding="utf-8") as f:
        f.write(report)

    return report
