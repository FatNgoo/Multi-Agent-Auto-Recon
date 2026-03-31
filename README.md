# ReconAI — Hướng Dẫn Sử Dụng

**Multi-Agent Attack Surface Scanner** | CrewAI + DeepSeek | Python 3.10+

---

## Mục Lục

1. [Tổng Quan Hệ Thống](#1-tổng-quan-hệ-thống)
2. [Yêu Cầu Cài Đặt](#2-yêu-cầu-cài-đặt)
3. [Cài Đặt Từng Bước](#3-cài-đặt-từng-bước)
4. [Cấu Hình API Keys](#4-cấu-hình-api-keys)
5. [Sử Dụng CLI (main.py)](#5-sử-dụng-cli-mainpy)
6. [Sử Dụng Web UI (app.py)](#6-sử-dụng-web-ui-apppy)
7. [Các Chế Độ Quét](#7-các-chế-độ-quét)
8. [Kết Quả Đầu Ra](#8-kết-quả-đầu-ra)
9. [Cấu Trúc Dự Án](#9-cấu-trúc-dự-án)
10. [Danh Sách Công Cụ](#10-danh-sách-công-cụ)
11. [Chạy Tests](#11-chạy-tests)
12. [Xử Lý Lỗi Thường Gặp](#12-xử-lý-lỗi-thường-gặp)
13. [Mục Tiêu Hợp Pháp Để Test](#13-mục-tiêu-hợp-pháp-để-test)

---

## 1. Tổng Quan Hệ Thống

ReconAI là hệ thống trinh sát tấn công bề mặt (Attack Surface Scanner) tự động, sử dụng kiến trúc **Multi-Agent** với 3 agent chuyên biệt hoạt động tuần tự:

```
Target Domain
    │
    ▼
┌─────────────────────────────┐
│  🔵 Passive Recon Agent     │  ← OSINT, Whois, DNS, Shodan, crt.sh, Wayback...
│  (14 passive tools)         │
└──────────────┬──────────────┘
               │ findings (JSON)
               ▼
┌─────────────────────────────┐
│  🔴 Active Recon Agent      │  ← Nmap, Banner, WAF, SSL, Headers, DirBust...
│  (15 active tools)          │
└──────────────┬──────────────┘
               │ findings (JSON)
               ▼
┌─────────────────────────────┐
│  🟢 Report Agent            │  ← CVE Lookup, Risk Score, AI Report Generator
│  (6 report tools)           │
└──────────────┬──────────────┘
               │
               ▼
    Attack Surface Report
    (MD / HTML / PDF)
```

**Công nghệ sử dụng:**

| Thành phần | Công nghệ |
|---|---|
| Multi-Agent Framework | CrewAI |
| LLM Backend | DeepSeek API (`deepseek-chat`) |
| Web UI | Streamlit |
| Passive Recon | Whois, crt.sh, Shodan, Subfinder, Wayback, URLScan... |
| Active Recon | Nmap, Masscan, Banner Grabbing, WAF Detection... |
| CVE Lookup | NVD API v2.0 |
| Report Export | Markdown → HTML → PDF |

---

## 2. Yêu Cầu Cài Đặt

### Phần mềm bắt buộc

- **Python 3.10+** (khuyến nghị 3.11)
- **Nmap** (cho active scanning)
- **Git** (để clone repo)

### Kiểm tra phiên bản

```bash
python --version    # >= 3.10
nmap --version      # >= 7.80
```

### Cài đặt Nmap

- **Windows:** Tải từ https://nmap.org/download.html → chạy installer → thêm vào PATH
- **Linux/Ubuntu:** `sudo apt-get install nmap`
- **macOS:** `brew install nmap`

---

## 3. Cài Đặt Từng Bước

### Bước 1: Clone Repository

```bash
git clone <repo_url>
cd multi_agent_recon
```

### Bước 2: Tạo Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python -m venv venv
source venv/bin/activate
```

### Bước 3: Cài Đặt Dependencies

```bash
pip install -r requirements.txt
```

**Lưu ý:** Một số thư viện tùy chọn:
- `weasyprint` — Xuất PDF (yêu cầu GTK trên Windows, xem https://doc.courtbouillon.org/weasyprint/)
- `pdfkit` + `wkhtmltopdf` — Thay thế xuất PDF

### Bước 4: Cấu Hình Environment

```bash
# Copy file mẫu
cp .env.example .env

# Mở file .env và điền API keys
```

---

## 4. Cấu Hình API Keys

Mở file `.env` và cấu hình:

```env
# ===== BẮT BUỘC =====
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ===== TÙY CHỌN (nâng cao kết quả) =====
SHODAN_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
URLSCAN_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
WHOXY_API_KEY=xxxxxxxxxxxxxxxx
VIEWDNS_API_KEY=xxxxxxxxxxxxxxxx
```

### Lấy API Keys miễn phí

| Service | URL | Ghi chú |
|---|---|---|
| DeepSeek | https://platform.deepseek.com | **Bắt buộc** — LLM backend |
| Shodan | https://account.shodan.io | Free tier: 1 lookup/giây |
| NVD | https://nvd.nist.gov/developers/request-an-api-key | Free, không giới hạn nhiều |
| URLScan | https://urlscan.io/user/signup | Free tier có sẵn |

---

## 5. Sử Dụng CLI (main.py)

### Quét cơ bản

```bash
python main.py --target scanme.nmap.org
```

### Xem tất cả tùy chọn

```bash
python main.py --help
```

```
usage: main.py [-h] [-t TARGET] [-m {full,passive,quick}]
               [--output-dir OUTPUT_DIR] [--list-sessions]
               [--no-resume] [--force] [--no-shodan] [--no-dorks]
               [--validate]

options:
  -h, --help            Hiển thị trợ giúp
  -t, --target TARGET   Domain mục tiêu (ví dụ: scanme.nmap.org)
  -m, --mode {full,passive,quick}
                        Chế độ quét (mặc định: full)
  --output-dir DIR      Thư mục lưu kết quả (mặc định: ./outputs)
  --list-sessions       Liệt kê các phiên quét đã lưu
  --no-resume           Không tiếp tục từ phiên cũ
  --force               Ghi đè kết quả cũ
  --no-shodan           Bỏ qua Shodan
  --no-dorks            Bỏ qua Google Dorks
  --validate            Kiểm tra môi trường trước khi quét
```

### Ví dụ sử dụng

```bash
# Quét đầy đủ
python main.py -t scanme.nmap.org -m full

# Chỉ OSINT thu thập thụ động
python main.py -t scanme.nmap.org -m passive

# Quét nhanh không Shodan và Dorks
python main.py -t testphp.vulnweb.com --no-shodan --no-dorks

# Kiểm tra môi trường
python main.py --validate

# Xem danh sách phiên đã lưu
python main.py --list-sessions

# Tiếp tục phiên cũ (mặc định nếu có dữ liệu passive)
python main.py -t scanme.nmap.org  
# (tự động resume nếu có outputs/sessions/scanme_nmap_org_passive.json)

# Bắt đầu lại từ đầu (ghi đè)
python main.py -t scanme.nmap.org --no-resume
```

---

## 6. Sử Dụng Web UI (app.py)

### Khởi động Streamlit UI

```bash
streamlit run app.py
```

Mở trình duyệt: http://localhost:8501

### Giao diện 3 Tab

#### Tab 1: 🔍 Reconnaissance

1. Nhập domain vào ô **Target Domain**
2. Chọn **Scan Mode** trong sidebar (Full / Passive / Quick)
3. Bật/tắt các tính năng tùy chọn (Shodan, Google Dorks, Wayback)
4. Nhấn **🚀 Start Scan**
5. Theo dõi tiến trình qua:
   - **Phase badges:** Passive → Active → Report
   - **Live Event Log:** Hiển thị từng hành động của agent

#### Tab 2: 📊 Intelligence Dashboard

Sau khi quét xong, tab này hiển thị:

- **Metric Cards:** Tổng findings, Critical/High/Medium, Subdomains, Open Ports
- **Severity Bar Chart:** Phân bố mức độ nghiêm trọng
- **Category Pie Chart:** Phân loại theo nhóm (Web Security, Network, OSINT...)
- **Findings Table:** Bảng chi tiết tất cả findings có thể sắp xếp
- **Infrastructure Summary:** Thông tin WHOIS, DNS, ASN

#### Tab 3: 📄 Report Viewer

- **Download MD:** Tải báo cáo Markdown
- **Download HTML:** Tải báo cáo HTML (dark theme)
- **Download PDF:** Tải báo cáo PDF
- **Rendered View:** Đọc báo cáo trực tiếp trong browser
- **Re-export:** Tái xuất HTML/PDF từ báo cáo MD đã có

### Sidebar Nhanh

```
⚙️ Scan Configuration
  Scan Mode: [Full / Passive / Quick]
  ✅ Shodan   ✅ Google Dorks
  ✅ Wayback  ✅ Save Session

🔑 API Status
  ✅ DeepSeek (Required)
  ✅ Shodan
  ❌ NVD (CVE)

📡 Recent Scans
  🔄 scanme.nmap.org  ← Click để điền target
```

---

## 7. Các Chế Độ Quét

### `full` — Đầy đủ (Mặc định)

**~15-20 phút** | Tất cả 3 agent

```
Passive Recon → Active Recon → Report Generation
```

Phù hợp: Kiểm tra toàn diện attack surface

### `passive` — OSINT Thụ Động

**~3-5 phút** | Chỉ Passive Recon Agent

```
Passive Recon → (basic report)
```

Phù hợp: Thu thập thông tin mà không gửi packet đến target

**Bao gồm:**
- Whois, DNS, Subdomain Enumeration
- Certificate Transparency (crt.sh)
- Shodan, IP/ASN lookup
- Email harvesting, Google Dorks
- Wayback Machine, URLScan
- ViewDNS, DNSDumpster

### `quick` — Quét Nhanh

**~5-10 phút** | Passive + Active (bỏ qua report đầy đủ)

```
Passive Recon → Active Recon → (summary report)
```

Phù hợp: Nhanh chóng kiểm tra open ports và banner

---

## 8. Kết Quả Đầu Ra

```
outputs/
├── sessions/               ← Dữ liệu thô để resume
│   ├── {target}_passive.json
│   └── {target}_active.json
├── reports/                ← Báo cáo cuối cùng
│   ├── attack_surface_report.md
│   ├── attack_surface_report.html
│   └── attack_surface_report.pdf
└── logs/                   ← Log hệ thống
```

### Cấu Trúc `_passive.json`

```json
{
  "target": "scanme.nmap.org",
  "scan_time": "2024-01-15T10:30:00",
  "whois": { "registrar": "...", "expiration_date": "..." },
  "dns_records": { "A": ["45.33.32.156"], "MX": [...] },
  "subdomains": [{"domain": "...", "ip": "...", "source": "..."}],
  "certificates": [...],
  "ip_asn": { "asn": "AS63949", "org": "Linode" },
  "shodan": { "open_ports": [22, 80], "vulns": [...] },
  "osint_emails": ["admin@example.com"],
  "wayback_urls": [...]
}
```

### Cấu Trúc Báo Cáo MD

Báo cáo Markdown bao gồm:

1. **Executive Summary** — Tóm tắt điều hành với risk score
2. **Target Profile** — Thông tin cơ bản về target
3. **Critical & High Findings** — Các lỗ hổng nghiêm trọng
4. **Attack Vectors** — Các vector tấn công tiềm năng
5. **Technical Details** — Chi tiết kỹ thuật từng finding
6. **CVE References** — Danh sách CVEs liên quan
7. **Remediation Roadmap** — Kế hoạch khắc phục ưu tiên
8. **Appendix** — Dữ liệu thống kê bổ sung

---

## 9. Cấu Trúc Dự Án

```
multi_agent_recon/
├── main.py                   ← CLI entry point
├── app.py                    ← Streamlit Web UI
├── requirements.txt          ← Python dependencies
├── .env.example              ← Mẫu environment variables
├── .env                      ← API keys (KHÔNG commit lên git)
├── .streamlit/
│   └── config.toml           ← Streamlit dark theme config
├── config/
│   └── llm_config.py         ← DeepSeek LLM configuration
├── agents/
│   ├── passive_recon_agent.py
│   ├── active_recon_agent.py
│   └── report_agent.py
├── tasks/
│   ├── passive_recon_task.py
│   ├── active_recon_task.py
│   └── report_task.py
├── crew/
│   └── recon_crew.py         ← Crew orchestrator
├── memory/
│   ├── session_manager.py    ← Session save/load/resume
│   └── context_manager.py   ← Token trimming
├── tools/
│   ├── passive/              ← 14 passive recon tools
│   ├── active/               ← 15 active recon tools
│   └── report/               ← 6 report generation tools
├── wordlists/
│   ├── directories_small.txt
│   ├── directories_medium.txt
│   └── subdomains_top100.txt
├── templates/
│   └── report_template.html
├── outputs/
│   ├── sessions/
│   ├── reports/
│   └── logs/
└── tests/
    ├── conftest.py
    ├── test_passive_tools.py
    ├── test_active_tools.py
    ├── test_report_tools.py
    └── fixtures/
        ├── sample_passive.json
        └── sample_active.json
```

---

## 10. Danh Sách Công Cụ

### Passive Recon Tools (14)

| Công cụ | Chức năng | API Key |
|---|---|---|
| `whois_tool` | Tra cứu thông tin đăng ký domain | Không |
| `dns_tool` | Enum DNS records (A, MX, NS, TXT, AAAA) | Không |
| `subdomain_tool` | Tìm subdomains (crt.sh, subfinder, brute-force) | Không |
| `certificate_tool` | Certificate Transparency (crt.sh) | Không |
| `shodan_tool` | Tìm kiếm trong Shodan database | **Shodan** |
| `ip_asn_tool` | IP/ASN lookup | Không |
| `theharvester_tool` | Email, username harvesting | Không |
| `email_validator_tool` | Kiểm tra email hợp lệ | Không |
| `google_dork_tool` | Google Dork queries | Không |
| `wayback_tool` | Wayback Machine URL history | Không |
| `dnsdumpster_tool` | DNS recon qua DNSDumpster | Không |
| `viewdns_tool` | Reverse IP, DNS history | ViewDNS |
| `urlscan_tool` | URLScan.io analysis | URLScan |
| `reverse_whois_tool` | Tìm domain theo email/org | Whoxy |

### Active Recon Tools (15)

| Công cụ | Chức năng | Yêu cầu |
|---|---|---|
| `nmap_tool` | Port scan + service detection | Nmap installed |
| `masscan_tool` | Nhanh hơn Nmap, full port scan | Masscan + root |
| `banner_tool` | Banner grabbing trên ports | Không |
| `whatweb_tool` | Web technology fingerprinting | Không |
| `ssl_tool` | SSL/TLS certificate & config analysis | Không |
| `headers_tool` | HTTP security headers analysis | Không |
| `dirbust_tool` | Directory/file brute forcing | Không |
| `waf_tool` | Web Application Firewall detection | Không |
| `techstack_tool` | Technology stack detection | Không |
| `robots_tool` | Robots.txt parsing | Không |
| `favicon_tool` | Favicon hash → tech fingerprint | Không |
| `crawler_tool` | Web crawler (links, forms, params) | Không |
| `param_tool` | URL parameter extraction | Không |
| `cloud_tool` | S3/Azure/GCS bucket discovery | Không |
| `http_method_tool` | Dangerous HTTP method check | Không |

### Report Tools (6)

| Công cụ | Chức năng |
|---|---|
| `compile_tool` | Gộp passive + active findings |
| `severity_tool` | Phân loại mức độ nghiêm trọng (AI-assisted) |
| `risk_scorer_tool` | Tính risk score 0-100 |
| `cve_tool` | Tra cứu CVEs từ NVD API |
| `report_gen_tool` | Tạo báo cáo chi tiết bằng AI |
| `export_tool` | Xuất MD → HTML → PDF |

---

## 11. Chạy Tests

```bash
# Cài pytest
pip install pytest pytest-cov

# Chạy tất cả tests
pytest tests/ -v

# Chạy tests với coverage
pytest tests/ -v --cov=. --cov-report=term-missing

# Chạy từng file test
pytest tests/test_passive_tools.py -v
pytest tests/test_active_tools.py -v
pytest tests/test_report_tools.py -v
```

---

## 12. Xử Lý Lỗi Thường Gặp

### ❌ `ModuleNotFoundError: No module named 'crewai'`

```bash
pip install -r requirements.txt
```

### ❌ `DEEPSEEK_API_KEY not set`

```bash
# Kiểm tra file .env có tồn tại không
cat .env  # Linux/macOS
type .env # Windows

# Nếu không có, tạo từ mẫu
cp .env.example .env
# Sau đó điền API key
```

### ❌ `nmap: command not found`

- Windows: Tải https://nmap.org/download.html và thêm vào PATH
- Linux: `sudo apt install nmap`
- macOS: `brew install nmap`

Hoặc dùng `--mode passive` để bỏ qua active scanning.

### ❌ Lỗi timeout khi quét

```bash
# Giảm scope quét
python main.py -t target.com --no-shodan --mode quick
```

### ❌ `WeasyPrint` không cài được trên Windows

Xuất PDF + HTML vẫn hoạt động qua `pdfkit`. Cài `wkhtmltopdf`:
- Tải: https://wkhtmltopdf.org/downloads.html
- Thêm vào PATH

Hoặc chỉ dùng HTML report (không cần weasyprint/pdfkit).

### ❌ Quét rất chậm

Nguyên nhân thường do:
1. DeepSeek API rate limit → Tool sẽ retry tự động
2. Nmap với full port scan → dùng `--mode passive` hoặc `quick`
3. Wayback Machine API chậm → tắt bằng `--no-wayback` (nếu được)

### ❌ `Error: Connection refused` khi Streamlit chạy

```bash
# Kiểm tra port
streamlit run app.py --server.port 8502
```

### ❌ Resume không hoạt động

```bash
# Kiểm tra session files
python main.py --list-sessions

# Buộc chạy lại từ đầu
python main.py -t target.com --no-resume
```

---

## 13. Mục Tiêu Hợp Pháp Để Test

> ⚠️ **CẢNH BÁO:** Chỉ scan các target bạn sở hữu hoặc có quyền kiểm tra bằng văn bản. Quét trái phép là vi phạm pháp luật.

### Target được phép test (sandbox/học tập)

| Target | Mô tả |
|---|---|
| `scanme.nmap.org` | Nmap's authorized test server (do nmap.org cung cấp) |
| `testphp.vulnweb.com` | Acunetix vulnerable web app (do Acunetix cung cấp) |
| `testhtml5.vulnweb.com` | Acunetix HTML5 test site |
| `testasp.vulnweb.com` | Acunetix ASP.NET test site |

### Kiểm tra trước khi quét

```bash
# Validate môi trường
python main.py --validate

# Test nhanh với passive only
python main.py -t scanme.nmap.org --mode passive
```

---

## Ví Dụ Output

Sau khi quét `scanme.nmap.org` với mode `full`, bạn sẽ nhận được:

```
┌──────────────────────────────────────────────────────────┐
│  SCAN RESULTS: scanme.nmap.org                           │
├──────────────────────────────────────────────────────────┤
│  Risk Score:    45/100 (Medium)                          │
│  Total Findings: 12                                      │
│  Critical: 0 | High: 2 | Medium: 4 | Low: 6             │
│  Subdomains:    4                                        │
│  Open Ports:    4 (22, 80, 9929, 31337)                  │
├──────────────────────────────────────────────────────────┤
│  Reports:                                                │
│  📄 outputs/reports/attack_surface_report.md             │
│  🌐 outputs/reports/attack_surface_report.html           │
│  📋 outputs/reports/attack_surface_report.pdf            │
└──────────────────────────────────────────────────────────┘
```

---

*ReconAI — Multi-Agent Attack Surface Scanner | Phiên bản 1.0*  
*Dự án cuối kỳ — Lập Trình Mạng*
