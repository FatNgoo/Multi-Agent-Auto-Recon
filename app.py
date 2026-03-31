# app.py — Streamlit Web UI for Multi-Agent Recon System
import streamlit as st
import json
import queue
import threading
import time
import os
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

# ─── PAGE CONFIG ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ReconAI — Multi-Agent Attack Surface Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CUSTOM CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark theme base */
    .stApp { background-color: #0a0e1a; color: #c9d1d9; }
    .stSidebar { background-color: #0d1117; }

    /* Metric cards */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #1a1f2e, #0f1419);
        border: 1px solid #2d3748;
        border-radius: 10px;
        padding: 15px;
    }

    /* Terminal log */
    .terminal-log {
        background-color: #0d1117;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 15px;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        max-height: 400px;
        overflow-y: auto;
    }

    /* Phase badges */
    .phase-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
        margin: 4px;
    }
    .phase-waiting  { background-color: #1c2128; color: #8b949e; }
    .phase-passive  { background-color: #1e3a5f; color: #4da6ff; }
    .phase-active   { background-color: #3d1f1f; color: #ff6b6b; }
    .phase-report   { background-color: #1f3d1f; color: #6bff6b; }
    .phase-done     { background-color: #1f3d1f; color: #00ff41; }

    /* Headers */
    h1, h2, h3 { color: #58a6ff; }

    /* Buttons */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #0070f3, #0055d4);
        color: white;
        border: none;
        border-radius: 8px;
    }

    /* Input */
    .stTextInput > div > div > input {
        background: #161b22;
        border: 1px solid #30363d;
        color: #c9d1d9;
        border-radius: 6px;
        font-size: 16px;
    }

    /* Divider */
    hr { border-color: #21262d; }

    /* Warning/info boxes */
    .stAlert { border-radius: 8px; }
</style>
""", unsafe_allow_html=True)


# ─── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ ReconAI")
    st.markdown("*Multi-Agent Attack Surface Scanner*")
    st.markdown("> CrewAI + DeepSeek | Python 3.10+")
    st.divider()

    st.markdown("### ⚙️ Scan Configuration")

    scan_mode = st.selectbox(
        "Scan Mode",
        ["full", "passive", "quick"],
        format_func=lambda x: {
            "full": "🔵 Full (Passive + Active + Report)",
            "passive": "🟡 Passive Only (OSINT)",
            "quick": "🔴 Quick Active",
        }.get(x, x),
        help="Full: ~15-20 min | Passive: ~3-5 min | Quick: ~5-10 min",
    )

    st.markdown("**Optional Features:**")
    col1, col2 = st.columns(2)
    with col1:
        enable_shodan = st.checkbox("Shodan", value=True)
        enable_dorks = st.checkbox("G.Dorks", value=True)
    with col2:
        enable_wayback = st.checkbox("Wayback", value=True)
        save_session = st.checkbox("Save", value=True, help="Save for resume")

    st.divider()

    # API key status
    st.markdown("### 🔑 API Status")
    deepseek_key = os.getenv("DEEPSEEK_API_KEY", "")
    shodan_key = os.getenv("SHODAN_API_KEY", "")
    nvd_key = os.getenv("NVD_API_KEY", "")

    def key_status(key, name):
        if key and len(key) > 5:
            st.markdown(f"✅ {name}")
        else:
            st.markdown(f"❌ {name}")

    key_status(deepseek_key, "DeepSeek (Required)")
    key_status(shodan_key, "Shodan")
    key_status(nvd_key, "NVD (CVE)")

    st.divider()

    # Recent sessions
    st.markdown("### 📡 Recent Scans")
    sessions_dir = Path("outputs/sessions")
    if sessions_dir.exists():
        session_files = sorted(
            sessions_dir.glob("*_passive.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )[:5]
        for sf in session_files:
            target_name = sf.stem.replace("_passive", "").replace("_", ".")
            if st.button(f"🔄 {target_name}", use_container_width=True, key=f"resume_{sf.stem}"):
                st.session_state["prefill_target"] = target_name
    else:
        st.caption("No previous scans")


# ─── STATE INITIALIZATION ─────────────────────────────────────────────────────
defaults = {
    "scan_running": False,
    "current_phase": "idle",
    "events": [],
    "findings": {},
    "report_content": None,
    "scan_start_time": None,
    "passive_done": False,
    "active_done": False,
    "report_done": False,
    "prefill_target": "",
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ─── MAIN TABS ─────────────────────────────────────────────────────────────────
tab_scan, tab_dashboard, tab_report = st.tabs([
    "🔍 Reconnaissance",
    "📊 Intelligence Dashboard",
    "📄 Report Viewer",
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════════════════
with tab_scan:
    st.markdown("## 🔍 Reconnaissance Control Panel")
    st.markdown(
        "> ⚠️ **Legal Notice:** Only scan targets you own or have explicit written permission to test. "
        "Authorized targets: `scanme.nmap.org`, `testphp.vulnweb.com`, your own domains."
    )

    # Input row
    col_input, col_btn = st.columns([5, 1])
    with col_input:
        prefill = st.session_state.get("prefill_target", "")
        target_input = st.text_input(
            "🎯 Target Domain",
            value=prefill,
            placeholder="Enter domain (e.g., scanme.nmap.org)",
            key="target_input",
            disabled=st.session_state.scan_running,
        )
    with col_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        start_btn = st.button(
            "🚀 Start Scan",
            type="primary",
            use_container_width=True,
            disabled=st.session_state.scan_running,
        )

    # Phase status indicators
    ph_col1, ph_col2, ph_col3 = st.columns(3)

    def phase_badge(label, state):
        cls = {
            "waiting": "phase-waiting",
            "running": "phase-passive",
            "done": "phase-done",
            "active_running": "phase-active",
            "report_running": "phase-report",
        }.get(state, "phase-waiting")
        return f'<span class="phase-badge {cls}">{label}</span>'

    passive_ph = ph_col1.empty()
    active_ph = ph_col2.empty()
    report_ph = ph_col3.empty()

    passive_ph.markdown(phase_badge("🔵 Passive Recon: Waiting", "waiting"), unsafe_allow_html=True)
    active_ph.markdown(phase_badge("🔴 Active Recon: Waiting", "waiting"), unsafe_allow_html=True)
    report_ph.markdown(phase_badge("🟢 Report: Waiting", "waiting"), unsafe_allow_html=True)

    # Progress bar
    progress_bar = st.empty()

    # Live event log
    st.markdown("### 📟 Live Event Log")
    log_container = st.empty()

    def render_terminal(events: list) -> str:
        level_colors = {
            "INFO": "#8b949e",
            "SUCCESS": "#00ff41",
            "WARN": "#e3b341",
            "ERROR": "#ff7b72",
            "TOOL": "#79c0ff",
        }
        lines = []
        for e in events[-60:]:
            color = level_colors.get(e.get("level", "INFO"), "#8b949e")
            ts = e.get("timestamp", "")
            ts_short = ts[11:19] if len(ts) >= 19 else ts
            agent = (e.get("agent") or "")[:12]
            msg = e.get("message", "")
            lines.append(
                f'<div style="margin:1px 0; color:{color}">'
                f'<span style="color:#484f58">{ts_short}</span> '
                f'<span style="color:#58a6ff">[{agent:<12}]</span> '
                f'{msg}'
                f'</div>'
            )
        return f'<div class="terminal-log">{"".join(lines)}</div>'

    # ── SCAN EXECUTION ─────────────────────────────────────────────────────────
    if start_btn and target_input and not st.session_state.scan_running:
        target = target_input.strip()

        # Reset state
        st.session_state.scan_running = True
        st.session_state.events = []
        st.session_state.passive_done = False
        st.session_state.active_done = False
        st.session_state.report_done = False
        st.session_state.scan_start_time = time.time()
        st.session_state.prefill_target = ""

        event_q = queue.Queue()
        result_holder = {}

        def run_crew_thread():
            try:
                from crew.recon_crew import ReconCrew
                crew = ReconCrew(
                    target=target,
                    event_queue=event_q,
                    scan_mode=scan_mode,
                    enable_shodan=enable_shodan,
                    enable_dorks=enable_dorks,
                    enable_wayback=enable_wayback,
                )
                result = crew.run()
                result_holder["result"] = result
                event_q.put({
                    "timestamp": datetime.now().isoformat(),
                    "level": "SUCCESS",
                    "agent": "SYSTEM",
                    "message": "✅ Scan completed successfully!",
                    "phase": "complete",
                })
            except Exception as exc:
                result_holder["error"] = str(exc)
                event_q.put({
                    "timestamp": datetime.now().isoformat(),
                    "level": "ERROR",
                    "agent": "SYSTEM",
                    "message": f"❌ Error: {exc}",
                    "phase": "error",
                })

        scan_thread = threading.Thread(target=run_crew_thread, daemon=True)
        scan_thread.start()

        # Live update loop
        progress_val = 0
        while scan_thread.is_alive():
            new_events = []
            while not event_q.empty():
                new_events.append(event_q.get())

            if new_events:
                st.session_state.events.extend(new_events)

                for ev in new_events:
                    phase = ev.get("phase", "")
                    msg = ev.get("message", "")

                    if "passive" in phase.lower() or "passive" in msg.lower():
                        passive_ph.markdown(
                            phase_badge("🔵 Passive Recon: Running...", "running"),
                            unsafe_allow_html=True,
                        )
                        progress_val = min(35, progress_val + 1)

                    elif "active" in phase.lower() or "active" in msg.lower():
                        passive_ph.markdown(
                            phase_badge("✅ Passive Recon: Done", "done"),
                            unsafe_allow_html=True,
                        )
                        active_ph.markdown(
                            phase_badge("🔴 Active Recon: Running...", "active_running"),
                            unsafe_allow_html=True,
                        )
                        progress_val = min(70, progress_val + 1)

                    elif "report" in phase.lower() or "report" in msg.lower():
                        active_ph.markdown(
                            phase_badge("✅ Active Recon: Done", "done"),
                            unsafe_allow_html=True,
                        )
                        report_ph.markdown(
                            phase_badge("🟢 Report: Writing...", "report_running"),
                            unsafe_allow_html=True,
                        )
                        progress_val = min(95, progress_val + 1)

                    elif "complete" in phase.lower():
                        progress_val = 100

            log_container.markdown(
                render_terminal(st.session_state.events),
                unsafe_allow_html=True,
            )
            progress_bar.progress(min(progress_val, 99) / 100)
            time.sleep(0.3)

        scan_thread.join(timeout=5)

        # Final state
        progress_bar.progress(1.0)
        passive_ph.markdown(phase_badge("✅ Passive Recon: Done", "done"), unsafe_allow_html=True)
        active_ph.markdown(phase_badge("✅ Active Recon: Done", "done"), unsafe_allow_html=True)
        report_ph.markdown(phase_badge("✅ Report: Done", "done"), unsafe_allow_html=True)
        st.session_state.scan_running = False

        if "result" in result_holder:
            res = result_holder["result"]
            st.session_state.findings = res
            elapsed = time.time() - st.session_state.scan_start_time
            st.success(f"✅ Scan completed in {elapsed:.0f}s! Switch to **Dashboard** or **Report** tabs.")
            st.balloons()
        else:
            st.error(f"❌ Scan failed: {result_holder.get('error', 'Unknown error')}")

    elif st.session_state.events:
        # Show previous events
        log_container.markdown(
            render_terminal(st.session_state.events),
            unsafe_allow_html=True,
        )

    # Instructions when idle
    if not st.session_state.scan_running and not st.session_state.events:
        st.info(
            "📋 **How to use:**\n"
            "1. Enter a target domain in the input above\n"
            "2. Configure scan options in the sidebar\n"
            "3. Click **Start Scan** to begin\n"
            "4. View results in **Dashboard** and **Report** tabs\n\n"
            "**Test target:** `scanme.nmap.org` (Nmap's authorized test server)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tab_dashboard:
    st.markdown("## 📊 Intelligence Dashboard")

    findings = st.session_state.get("findings", {})

    if not findings:
        st.info("👆 Run a scan in the **Reconnaissance** tab to see data here.")
    else:
        try:
            import plotly.express as px
            import plotly.graph_objects as go
            import pandas as pd

            stats = findings.get("statistics", {})
            sev = stats.get("severity_breakdown", {})

            # ── Metric Cards ──────────────────────────────────────────────────
            m1, m2, m3, m4, m5, m6 = st.columns(6)
            m1.metric("🔍 Findings", stats.get("total_findings", 0))
            m2.metric("🔴 Critical", sev.get("Critical", 0))
            m3.metric("🟠 High", sev.get("High", 0))
            m4.metric("🟡 Medium", sev.get("Medium", 0))
            m5.metric("🌐 Subdomains", stats.get("subdomains_count", 0))
            m6.metric("🔌 Open Ports", stats.get("open_ports_count", 0))

            st.divider()

            # ── Charts ────────────────────────────────────────────────────────
            col_c1, col_c2 = st.columns(2)

            with col_c1:
                # Severity Bar Chart
                sev_data = {
                    "Severity": ["Critical", "High", "Medium", "Low", "Info"],
                    "Count": [
                        sev.get("Critical", 0),
                        sev.get("High", 0),
                        sev.get("Medium", 0),
                        sev.get("Low", 0),
                        sev.get("Info", 0),
                    ],
                }
                fig_sev = px.bar(
                    sev_data, x="Severity", y="Count",
                    color="Severity",
                    color_discrete_map={
                        "Critical": "#ff4444",
                        "High": "#ff8800",
                        "Medium": "#ffcc00",
                        "Low": "#4488ff",
                        "Info": "#888888",
                    },
                    title="Findings by Severity",
                    template="plotly_dark",
                )
                fig_sev.update_layout(showlegend=False, height=350)
                st.plotly_chart(fig_sev, use_container_width=True)

            with col_c2:
                # Category Pie Chart
                cat_data = stats.get("category_breakdown", {})
                if not cat_data:
                    cat_data = {
                        "Web Security": sev.get("High", 0) + sev.get("Medium", 0),
                        "Network": stats.get("open_ports_count", 0),
                        "OSINT": stats.get("osint_findings_count", 0),
                        "Infrastructure": stats.get("infrastructure_findings_count", 0),
                        "SSL/TLS": max(sev.get("Critical", 0) - 1, 0),
                    }
                    cat_data = {k: v for k, v in cat_data.items() if v > 0}

                if cat_data:
                    fig_pie = px.pie(
                        values=list(cat_data.values()),
                        names=list(cat_data.keys()),
                        title="Findings by Category",
                        template="plotly_dark",
                        hole=0.4,
                        color_discrete_sequence=px.colors.qualitative.Bold,
                    )
                    fig_pie.update_layout(height=350)
                    st.plotly_chart(fig_pie, use_container_width=True)

            # ── All Findings Table ────────────────────────────────────────────
            all_findings_list = findings.get("all_findings_list", [])
            if all_findings_list:
                st.markdown("### 🗂️ All Findings")
                df = pd.DataFrame(all_findings_list)
                available_cols = [c for c in ["title", "severity", "cvss_score", "category", "host"]
                                  if c in df.columns]
                if available_cols:
                    display_df = df[available_cols].sort_values(
                        "cvss_score" if "cvss_score" in available_cols else available_cols[0],
                        ascending=False,
                    )
                    st.dataframe(display_df, use_container_width=True, hide_index=True)

            # ── Infrastructure Summary ────────────────────────────────────────
            st.markdown("### 🌐 Target Information")
            target_info = findings.get("target", "N/A")
            passive_path = "outputs/sessions/findings_passive.json"
            if Path(passive_path).exists():
                try:
                    with open(passive_path, "r", encoding="utf-8") as f:
                        passive = json.load(f)

                    whois_info = passive.get("whois", {})
                    infra_cols = st.columns(3)
                    with infra_cols[0]:
                        st.markdown("**WHOIS Info**")
                        st.write(f"Registrar: {whois_info.get('registrar', 'N/A')}")
                        st.write(f"Expires: {whois_info.get('expiration_date', 'N/A')}")
                        st.write(f"Org: {whois_info.get('registrant_org', 'N/A')}")
                    with infra_cols[1]:
                        st.markdown("**DNS Records**")
                        dns = passive.get("dns_records", {})
                        st.write(f"A Records: {', '.join(dns.get('A', [])[:3])}")
                        st.write(f"MX Records: {len(dns.get('MX', []))} found")
                        st.write(f"NS Records: {len(dns.get('NS', []))} found")
                    with infra_cols[2]:
                        st.markdown("**ASN Info**")
                        asn = passive.get("asn_info", {})
                        st.write(f"ASN: {asn.get('asn', 'N/A')}")
                        st.write(f"Org: {asn.get('org', 'N/A')}")
                        st.write(f"Country: {asn.get('country', 'N/A')}")
                except Exception:
                    pass

        except ImportError:
            st.error("📦 Install dependencies: `pip install plotly pandas`")
        except Exception as e:
            st.error(f"Dashboard error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: REPORT VIEWER
# ══════════════════════════════════════════════════════════════════════════════
with tab_report:
    st.markdown("## 📄 Attack Surface Report")

    report_md_path = Path("outputs/reports/attack_surface_report.md")
    report_html_path = Path("outputs/reports/attack_surface_report.html")
    report_pdf_path = Path("outputs/reports/attack_surface_report.pdf")

    if not report_md_path.exists():
        st.info("👆 Run a scan to generate the Attack Surface Report.")

        # Show sample path info
        st.markdown("**Report will be saved at:**")
        st.code("outputs/reports/attack_surface_report.md\noutputs/reports/attack_surface_report.html\noutputs/reports/attack_surface_report.pdf")
    else:
        # Download buttons
        dl_col1, dl_col2, dl_col3, _ = st.columns([1, 1, 1, 3])

        report_md_content = report_md_path.read_text(encoding="utf-8")

        with dl_col1:
            st.download_button(
                "📥 Download MD",
                data=report_md_content,
                file_name="attack_surface_report.md",
                mime="text/markdown",
                use_container_width=True,
            )

        with dl_col2:
            if report_html_path.exists():
                st.download_button(
                    "📥 Download HTML",
                    data=report_html_path.read_bytes(),
                    file_name="attack_surface_report.html",
                    mime="text/html",
                    use_container_width=True,
                )

        with dl_col3:
            if report_pdf_path.exists():
                st.download_button(
                    "📥 Download PDF",
                    data=report_pdf_path.read_bytes(),
                    file_name="attack_surface_report.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )

        st.divider()

        # View options
        view_mode = st.radio(
            "View mode:",
            ["Rendered", "Raw Markdown"],
            horizontal=True,
        )

        if view_mode == "Rendered":
            st.markdown(report_md_content)
        else:
            st.code(report_md_content, language="markdown")

        # Show report file info
        mod_time = datetime.fromtimestamp(report_md_path.stat().st_mtime)
        st.caption(
            f"Report generated: {mod_time.strftime('%Y-%m-%d %H:%M:%S')} | "
            f"Size: {len(report_md_content):,} characters"
        )

        # Quick re-export
        if st.button("🔄 Re-export HTML & PDF"):
            with st.spinner("Exporting..."):
                try:
                    from tools.report.export_tool import export_report
                    result_json = export_report(
                        json.dumps({"report_path": str(report_md_path)})
                    )
                    result = json.loads(result_json)
                    if result.get("html_exported"):
                        st.success(f"✅ HTML exported: {result['files'].get('html')}")
                    if result.get("pdf_exported"):
                        st.success(f"✅ PDF exported: {result['files'].get('pdf')}")
                    if result.get("errors"):
                        for err in result["errors"]:
                            st.warning(f"⚠️ {err}")
                except Exception as ex:
                    st.error(f"Export error: {ex}")
