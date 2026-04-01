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

Tất cả findings đã được lưu vào files. Các tool sẽ TỰ ĐỘNG đọc từ disk.
Thực hiện ĐÚNG THỨ TỰ các bước sau — mỗi bước gọi tool MỘT LẦN:

### Bước 1: Compile
Gọi compile_all_findings("{target}")
Tool sẽ tự đọc từ outputs/sessions/findings_passive.json và findings_active.json.

### Bước 2: CVE Lookup (tối đa 3 service quan trọng nhất)
Chọn tối đa 3 versioned service từ kết quả compile (ví dụ: nginx, openssh, apache) và gọi:
cve_lookup({{"service": "<tên>", "version": "<version>"}})
Nếu không có versioned service nào, bỏ qua bước này.

### Bước 3: Risk Score
Gọi risk_scorer("{target}")
Tool sẽ tự đọc compiled findings từ disk.

### Bước 4: Generate Report
Gọi report_generator("{target}")
Tool sẽ tự đọc compiled findings và risk score từ disk.

### Bước 5: Export
Gọi export_report với JSON: {{"report_path": "outputs/reports/attack_surface_report.md"}}
QUAN TRỌNG: KHÔNG truyền markdown_content — chỉ dùng report_path.

### DỪNG NGAY
Sau khi export_report trả về kết quả (dù thành công hay lỗi), KHÔNG gọi thêm tool nào nữa.
Trả lời ngay: "Báo cáo đã được tạo tại outputs/reports/attack_surface_report.md"
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

1. compile_all_findings("{target}") — tự đọc từ session files
2. risk_scorer("{target}") — tự đọc compiled findings
3. report_generator("{target}") — tự đọc compiled + risk score
4. export_report({{"report_path": "outputs/reports/attack_surface_report.md"}})

DỪNG NGAY sau khi export_report hoàn tất.
""",
        expected_output="Attack Surface Report đầy đủ",
        agent=report_agent,
        output_file="outputs/reports/attack_surface_report.md",
    )


# Default instance
task_report = create_report_task_simple("TARGET_PLACEHOLDER")
