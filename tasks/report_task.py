# tasks/report_task.py
import os
from crewai import Task
from agents.report_agent import report_agent


def create_report_task(target: str, passive_task: Task, active_task: Task) -> Task:
    """Create the report generation task."""
    os.makedirs("outputs/reports", exist_ok=True)

    return Task(
        description=f"""
## NHIỆM VỤ: TẠO BÁO CÁO ATTACK SURFACE

**Target:** {target}

Bạn có toàn bộ findings từ passive và active recon trong context.
Hãy suy nghĩ từng bước (Chain-of-Thought) để tạo báo cáo hoàn chỉnh:

### CoT Step 1: Compile & Normalize
- compile_all_findings({{"passive": <passive_data>, "active": <active_data>}})
- Merge tất cả findings vào một dataset thống nhất
- Loại bỏ duplicates, normalize format

### CoT Step 2: CVE & Vulnerability Research
- Với mỗi service version tìm được trong active scan:
  cve_lookup({{"service": "nginx", "version": "1.18.0"}}) cho từng service
- Tìm tối thiểu top CVE phổ biến nhất (nếu có versioned services)

### CoT Step 3: Risk Classification
- severity_classifier(<finding_json>) cho mỗi finding quan trọng
- Phân loại: Critical (9-10), High (7-8.9), Medium (4-6.9), Low (0.1-3.9), Info (0)
- risk_scorer(<all_findings_json>) → overall risk score

### CoT Step 4: Generate Report
- report_generator(<merged_data_json>) → Markdown report đầy đủ

### CoT Step 5: Export
- export_report({{"report_path": "outputs/reports/attack_surface_report.md"}})

### Sections BẮT BUỘC trong báo cáo:
1. Executive Summary (200-300 từ, không tech jargon)
2. Scope & Methodology
3. Attack Surface Overview
4. Findings Summary Table (ID, Severity, Category, Title, CVSS)
5. Detailed Technical Findings (description, evidence, impact, recommendation)
6. Risk Matrix (Likelihood vs Impact)
7. Remediation Roadmap (Immediate/Short/Long-term)
8. Appendix (raw data summary, tools used)

### Yêu cầu chất lượng:
- Mỗi Critical/High finding phải có CVE reference nếu có thể
- Executive Summary readable cho non-technical stakeholder
- Recommendations phải cụ thể, có thể thực hiện ngay
""",
        expected_output=f"""Báo cáo Attack Surface hoàn chỉnh cho {target}:
- outputs/reports/attack_surface_report.md
- outputs/reports/attack_surface_report.html
- outputs/reports/attack_surface_report.pdf
Kèm theo risk score tổng thể (0-100) và danh sách top findings.""",
        agent=report_agent,
        context=[passive_task, active_task],
        output_file="outputs/reports/attack_surface_report.md",
    )


def create_report_task_simple(target: str) -> Task:
    """Create report task without context dependency."""
    os.makedirs("outputs/reports", exist_ok=True)

    return Task(
        description=f"""
## REPORT for {target}

Tạo báo cáo Attack Surface cho {target}:

1. Đọc findings từ files:
   - outputs/sessions/findings_passive.json (nếu có)
   - outputs/sessions/findings_active.json (nếu có)

2. compile_all_findings với data đọc được

3. risk_scorer để tính điểm rủi ro

4. report_generator để tạo báo cáo Markdown

5. export_report để xuất HTML và PDF

Output: Báo cáo đầy đủ tại outputs/reports/attack_surface_report.md
""",
        expected_output="Attack Surface Report đầy đủ",
        agent=report_agent,
        output_file="outputs/reports/attack_surface_report.md",
    )


# Default instance
task_report = create_report_task_simple("TARGET_PLACEHOLDER")
