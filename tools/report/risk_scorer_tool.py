# tools/report/risk_scorer_tool.py
import json
import os
from openai import OpenAI
from crewai.tools import tool

COMPILED_PATH = "outputs/sessions/compiled_findings.json"
RISK_PATH = "outputs/sessions/risk_score.json"


@tool("Overall Risk Scorer")
def risk_scorer(target: str) -> str:
    """
    Tính điểm rủi ro tổng thể (0-100) cho toàn bộ attack surface dựa trên
    tất cả findings đã compiled. Tự động đọc từ compiled_findings.json.
    Input: target domain (ví dụ: hcmute.edu.vn)
    """
    # Read compiled findings from disk
    if os.path.exists(COMPILED_PATH):
        try:
            with open(COMPILED_PATH, "r", encoding="utf-8") as f:
                findings = json.load(f)
        except Exception:
            return json.dumps({"error": f"Could not read {COMPILED_PATH}"})
    else:
        return json.dumps({"error": f"File not found: {COMPILED_PATH}. Run compile_all_findings first."})

    # Rule-based scoring first
    stats = findings.get("statistics", {})
    sev = stats.get("severity_breakdown", {})

    critical = sev.get("Critical", 0)
    high = sev.get("High", 0)
    medium = sev.get("Medium", 0)
    low = sev.get("Low", 0)

    # Weighted score calculation
    raw_score = (
        critical * 25 +
        high * 10 +
        medium * 4 +
        low * 1
    )

    # Normalize to 0-100
    base_score = min(100, raw_score)

    # Adjust for infrastructure exposure
    open_ports = stats.get("open_ports_count", 0)
    subdomains = stats.get("subdomains_count", 0)

    if open_ports > 20:
        base_score = min(100, base_score + 5)
    if subdomains > 50:
        base_score = min(100, base_score + 5)

    # Risk level classification
    if base_score >= 80:
        risk_level = "Critical"
        risk_color = "#FF0000"
    elif base_score >= 60:
        risk_level = "High"
        risk_color = "#FF6600"
    elif base_score >= 40:
        risk_level = "Medium"
        risk_color = "#FFCC00"
    elif base_score >= 20:
        risk_level = "Low"
        risk_color = "#00AAFF"
    else:
        risk_level = "Minimal"
        risk_color = "#00FF00"

    # Try to get AI-enhanced analysis
    ai_summary = None
    api_key = os.getenv("DEEPSEEK_API_KEY")

    if api_key:
        try:
            client = OpenAI(
                api_key=api_key,
                base_url="https://api.deepseek.com",
            )

            summary_data = {
                "target": findings.get("meta", {}).get("target"),
                "severity_breakdown": sev,
                "open_ports": open_ports,
                "subdomains": subdomains,
                "score": base_score,
                "risk_level": risk_level,
            }

            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Bạn là security analyst. Viết tóm tắt ngắn (3-4 câu) về mức độ rủi ro "
                            "dựa trên data được cung cấp. Viết bằng tiếng Việt. Chỉ trả lời text thuần, không JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"Tóm tắt rủi ro:\n{json.dumps(summary_data, ensure_ascii=False)}",
                    },
                ],
                max_tokens=200,
                temperature=0.2,
            )

            ai_summary = response.choices[0].message.content.strip()
        except Exception:
            pass

    # Build risk matrix
    risk_matrix = []
    web_findings = findings.get("web_findings", [])
    services = findings.get("services", [])
    infra_findings = findings.get("infrastructure_findings", [])

    all_findings = web_findings + services + infra_findings
    for f in all_findings:
        sev_val = f.get("severity", "Info")
        likelihood_map = {
            "Critical": "High",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Info": "Low",
        }
        impact_map = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Info": "Info",
        }
        risk_matrix.append({
            "title": f.get("title", f.get("service", "Unknown")),
            "severity": sev_val,
            "likelihood": likelihood_map.get(sev_val, "Medium"),
            "impact": impact_map.get(sev_val, "Medium"),
        })

    result = {
        "target": findings.get("meta", {}).get("target"),
        "overall_risk_score": base_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "severity_breakdown": sev,
        "ai_summary": ai_summary,
        "risk_matrix": risk_matrix[:20],
        "top_risks": [
            f for f in all_findings
            if f.get("severity") in ["Critical", "High"]
        ][:5],
        "remediation_priority": {
            "immediate": [f.get("title", "") for f in all_findings if f.get("severity") == "Critical"][:5],
            "short_term": [f.get("title", "") for f in all_findings if f.get("severity") == "High"][:5],
            "long_term": [f.get("title", "") for f in all_findings if f.get("severity") == "Medium"][:5],
        },
    }

    # Save risk score to disk so report_generator can read it
    os.makedirs("outputs/sessions", exist_ok=True)
    with open(RISK_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    # Return compact summary
    return json.dumps({
        "status": "success",
        "risk_path": RISK_PATH,
        "overall_risk_score": base_score,
        "risk_level": risk_level,
        "severity_breakdown": sev,
        "ai_summary": ai_summary,
        "instruction": (
            "Risk score saved. "
            "Next: call report_generator with target name to generate the report."
        ),
    }, ensure_ascii=False, indent=2)
