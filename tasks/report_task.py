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
Thực hiện ĐÚNG THỨ TỰ các bước sau — mỗi bước gọi tool MỘT LẦN:

### Bước 1: Compile
Gọi compile_all_findings một lần với toàn bộ context (passive + active).

### Bước 2: CVE Lookup (tối đa 3 service quan trọng nhất)
Chọn tối đa 3 versioned service (ví dụ: nginx, openssh, apache) và gọi:
cve_lookup({{"service": "<tên>", "version": "<version>"}})
Nếu không có versioned service nào, bỏ qua bước này.

### Bước 3: Risk Score
Gọi risk_scorer một lần với toàn bộ findings đã compile.

### Bước 4: Generate Report
Gọi report_generator một lần với merged data từ các bước trên.
Báo cáo Markdown phải có:
- Executive Summary (non-technical, 200-300 từ)
- Attack Surface Overview
- Findings Summary Table (Severity, Title, CVSS)
- Top Findings với evidence và recommendation
- Remediation Roadmap (Immediate / Short / Long-term)

### Bước 5: Export
Gọi export_report với JSON: {{"report_path": "outputs/reports/attack_surface_report.md"}}
QUAN TRỌNG: KHÔNG truyền markdown_content vào export_report — chỉ dùng report_path.
File đã được lưu bởi report_generator ở bước trước.
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
