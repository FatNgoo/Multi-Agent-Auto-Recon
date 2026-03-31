# tools/report/severity_tool.py
import json
import os
from openai import OpenAI
from crewai.tools import tool


SEVERITY_SYSTEM_PROMPT = """Bạn là chuyên gia bảo mật thông tin, thành thạo CVSS v3.1 scoring system.
Phân tích security finding và trả về CHÍNH XÁC một JSON object.
KHÔNG trả về text nào khác ngoài JSON.

JSON format bắt buộc:
{
  "severity": "Critical|High|Medium|Low|Info",
  "cvss_score": <float 0.0-10.0>,
  "cvss_vector": "CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?",
  "attack_vector": "Network|Adjacent|Local|Physical",
  "attack_complexity": "Low|High",
  "privileges_required": "None|Low|High",
  "user_interaction": "None|Required",
  "impact_confidentiality": "None|Low|High",
  "impact_integrity": "None|Low|High",
  "impact_availability": "None|Low|High",
  "reasoning": "<50 từ giải thích ngắn gọn tại sao score này>"
}

Ví dụ:
- "Missing HSTS header" → severity: Medium, score: 4.3
- "nginx 1.14 - known CVEs" → severity: High, score: 7.5  
- "OpenSSL 1.0.1 Heartbleed" → severity: Critical, score: 9.8
- "Information Disclosure - emails found" → severity: Low, score: 3.1
"""


@tool("Security Finding Severity Classifier")
def severity_classifier(finding_json: str) -> str:
    """
    Phân loại mức độ nghiêm trọng của security finding theo CVSS v3.1.
    Sử dụng DeepSeek AI để phân tích và cho điểm CVSS.
    Input: JSON string mô tả finding (title, category, detail, host)
    """
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        return json.dumps({
            "error": "DEEPSEEK_API_KEY not set",
            "severity": "Medium",
            "cvss_score": 5.0,
            "reasoning": "Default score - API key not configured",
        })

    try:
        finding = json.loads(finding_json)
    except Exception:
        finding = {"title": finding_json}

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com",
    )

    user_prompt = f"Phân loại finding sau:\n{json.dumps(finding, ensure_ascii=False, indent=2)}"

    for attempt in range(2):
        try:
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": SEVERITY_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=400,
                temperature=0.0,
            )

            content = response.choices[0].message.content.strip()

            # Strip markdown code blocks if present
            if content.startswith("```"):
                lines = content.split("\n")
                content = "\n".join(lines[1:-1]) if len(lines) > 2 else content

            result = json.loads(content)

            # Validate required fields
            required = ["severity", "cvss_score"]
            if any(k not in result for k in required):
                raise ValueError("Missing required fields in response")

            return json.dumps(result, ensure_ascii=False, indent=2)

        except json.JSONDecodeError:
            if attempt == 0:
                continue
            return json.dumps({
                "error": "Failed to parse LLM response",
                "severity": "Medium",
                "cvss_score": 5.0,
                "raw": content if "content" in dir() else "",
            })
        except Exception as e:
            if attempt == 1:
                return json.dumps({
                    "error": str(e),
                    "severity": "Medium",
                    "cvss_score": 5.0,
                })
