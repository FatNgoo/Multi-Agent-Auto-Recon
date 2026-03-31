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
QUAN TRỌNG: Chỉ viết những gì có evidence từ data. Không fabricate findings."""


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

    target = (data.get("meta", {}).get("target") or
              data.get("target", "Unknown Target"))

    # Prepare summary for LLM (trim to avoid token overflow)
    stats = data.get("statistics", {})
    sev = stats.get("severity_breakdown", {})

    services = data.get("services", [])
    web_findings = data.get("web_findings", [])
    osint_findings = data.get("osint_findings", [])
    infra_findings = data.get("infrastructure_findings", [])

    # Top findings for report
    all_findings = (
        [f for f in infra_findings if f.get("severity") == "Critical"] +
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
            "open_ports": stats.get("open_ports_count", 0),
        },
        "infrastructure": data.get("infrastructure", {}),
        "key_findings": all_findings,
        "versioned_services": versioned_services,
        "risk_score": data.get("overall_risk_score"),
        "risk_level": data.get("risk_level"),
    }

    user_prompt = f"""
<analysis>
**Bước 1 — Đánh giá tổng quan target:**
- Target: {target}
- Subdomains: {stats.get("subdomains_count", 0)}
- Open ports: {stats.get("open_ports_count", 0)}
- Risk score: {data.get("overall_risk_score", "N/A")}/100

**Bước 2 — Top rủi ro từ findings:**
Critical: {sev.get("Critical", 0)}, High: {sev.get("High", 0)}, Medium: {sev.get("Medium", 0)}

**Bước 3 — Business impact analysis:**
Đánh giá khả năng khai thác và tác động kinh doanh của các findings quan trọng.
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
[Tổng quan infrastructure: domains, IPs, services, entry points]

## 4. Findings Summary

| ID | Severity | Category | Title | CVSS Score |
|---|---|---|---|---|
[Liệt kê tất cả findings từ data, tối thiểu 10 findings]

## 5. Detailed Technical Findings
[Với mỗi finding quan trọng (Critical/High/Medium):
### FIND-XXX — Title
**Severity:** | **CVSS:** | **Category:**
**Description:** [kỹ thuật]
**Evidence:** [từ scan data]
**Impact:** [business + technical]
**Recommendation:** [steps cụ thể]
**References:** [CVE/OWASP links nếu có]
]

## 6. Risk Matrix

| Likelihood\Impact | Critical | High | Medium | Low |
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

        return report_md

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
