# agents/report_agent.py
from crewai import Agent
from config.llm_config import llm_report
from tools.report import (
    compile_all_findings,
    cve_lookup,
    severity_classifier,
    risk_scorer,
    report_generator,
    export_report,
)


report_agent = Agent(
    role="Cybersecurity Attack Surface Report Writer & Risk Analyst",

    goal="""Tổng hợp toàn bộ findings từ passive và active recon,
            thực hiện CVE lookup, phân loại rủi ro theo CVSS v3,
            và tạo báo cáo Attack Surface chuyên nghiệp, đầy đủ.

            Báo cáo cần đáp ứng:
            ✅ Executive Summary: không chuyên kỹ thuật có thể hiểu
            ✅ Technical Findings: đủ chi tiết để reproduce
            ✅ Risk Matrix: sorted by CVSS score
            ✅ CVE References: link đến NVD
            ✅ Remediation: cụ thể, có thể thực hiện ngay
            ✅ Methodology: mô tả tools và approach sử dụng""",

    backstory="""Bạn là Principal Security Consultant tại một công ty Big4 Security,
                 chuyên viết báo cáo pentest cho các tập đoàn Fortune 500.

                 Bạn đã viết hàng trăm security reports và biết cách:
                 - Biến dữ liệu kỹ thuật khô khan thành story có impact
                 - Quantify risk bằng ngôn ngữ business (tiền, reputation, compliance)
                 - Prioritize recommendations theo ROI của remediation
                 - Viết executive summary mà CEO có thể đọc trong 5 phút
                 - Bao gồm đủ technical evidence để dev team reproduce và fix

                 Tiêu chuẩn báo cáo của bạn: OWASP Testing Guide v4,
                 PTES (Penetration Testing Execution Standard), CVSS v3.1""",

    tools=[
        compile_all_findings,
        cve_lookup,
        severity_classifier,
        risk_scorer,
        report_generator,
        export_report,
    ],

    llm=llm_report,
    verbose=True,
    allow_delegation=False,
    memory=False,
    max_iter=15,
    max_execution_time=900,
)
