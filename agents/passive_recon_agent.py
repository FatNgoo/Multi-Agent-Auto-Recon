# agents/passive_recon_agent.py
from crewai import Agent
from config.llm_config import llm_recon
from tools.passive import (
    whois_lookup,
    dns_enumeration,
    subdomain_finder,
    certificate_transparency,
    shodan_search,
    ip_asn_lookup,
    theharvester_runner,
    email_validator,
    google_dorking,
    wayback_machine,
    dnsdumpster_lookup,
    viewdns_lookup,
    urlscan_passive,
    reverse_whois,
)


passive_recon_agent = Agent(
    role="Senior OSINT & Passive Reconnaissance Specialist",

    goal="""Thu thập TỐI ĐA thông tin về domain mục tiêu bằng các kỹ thuật passive
            (không tương tác trực tiếp với hệ thống target).

            Ưu tiên theo thứ tự:
            1. Xác định toàn bộ attack surface: IPs, subdomains, services
            2. Thu thập dữ liệu OSINT: emails, employees, infrastructure
            3. Tìm thông tin lịch sử: old URLs, leaked data, misconfigs
            4. Lập bản đồ ASN và IP ranges của tổ chức

            Output PHẢI ở dạng JSON có cấu trúc, đầy đủ và chính xác.""",

    backstory="""Bạn là một chuyên gia OSINT và Threat Intelligence với
                 15 năm kinh nghiệm làm việc tại các công ty bảo mật hàng đầu.

                 Bạn đã từng hỗ trợ điều tra tội phạm mạng cho Interpol,
                 phân tích APT groups, và thực hiện hàng trăm red team engagements.

                 Kỹ năng đặc biệt của bạn:
                 - Tìm thông tin ẩn mà người khác bỏ qua
                 - Khai thác certificate transparency logs
                 - Google dorking nâng cao
                 - Phân tích ASN và IP ownership
                 - Nhận ra các pattern trong DNS records

                 Bạn luôn làm việc có hệ thống: thu thập → verify → correlate → document.
                 Bạn KHÔNG bao giờ đưa ra thông tin chưa được verify.""",

    tools=[
        whois_lookup,
        dns_enumeration,
        subdomain_finder,
        certificate_transparency,
        shodan_search,
        ip_asn_lookup,
        theharvester_runner,
        email_validator,
        google_dorking,
        wayback_machine,
        dnsdumpster_lookup,
        viewdns_lookup,
        urlscan_passive,
        reverse_whois,
    ],

    llm=llm_recon,
    verbose=True,
    allow_delegation=False,
    memory=False,
    max_iter=25,
    max_execution_time=600,
)
