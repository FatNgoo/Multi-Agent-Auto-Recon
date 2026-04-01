# crew/recon_crew.py
import os
import queue
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from crewai import Crew, Process
from agents.passive_recon_agent import passive_recon_agent
from agents.active_recon_agent import active_recon_agent
from agents.report_agent import report_agent
from tasks.passive_recon_task import create_passive_recon_task
from tasks.active_recon_task import create_active_recon_task
from tasks.report_task import create_report_task

logger = logging.getLogger(__name__)


class ReconCrew:
    """
    Orchestrates the Multi-Agent Recon System.
    Runs 3 agents sequentially: Passive → Active → Report.
    """

    def __init__(
        self,
        target: str,
        event_queue: Optional[queue.Queue] = None,
        event_callback: Optional[Callable] = None,
        scan_mode: str = "full",
        enable_shodan: bool = True,
        enable_dorks: bool = True,
        enable_wayback: bool = True,
    ):
        self.target = target.strip().lower()
        # Remove protocol prefix if given
        for prefix in ["http://", "https://", "www."]:
            if self.target.startswith(prefix):
                self.target = self.target[len(prefix):]

        self.event_queue = event_queue
        self.event_callback = event_callback
        self.scan_mode = scan_mode  # "full", "passive", "quick"
        self.enable_shodan = enable_shodan
        self.enable_dorks = enable_dorks
        self.enable_wayback = enable_wayback

        # Ensure output directories exist
        os.makedirs("outputs/sessions", exist_ok=True)
        os.makedirs("outputs/reports", exist_ok=True)
        os.makedirs("outputs/logs", exist_ok=True)

    def _emit(self, level: str, agent: str, message: str, phase: str = ""):
        """Emit an event to the queue or callback."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "agent": agent,
            "message": message,
            "phase": phase,
        }
        if self.event_queue:
            self.event_queue.put(event)
        if self.event_callback:
            self.event_callback(event)
        logger.info(f"[{level}] [{agent}] {message}")

    def run(self) -> dict:
        """
        Execute the full recon pipeline.
        Returns dict with paths to all output files.
        """
        start_time = datetime.now()
        self._emit("INFO", "SYSTEM", f"🚀 Starting scan for target: {self.target}", "init")

        # Validate target
        if not self.target or len(self.target) < 3:
            return {"status": "error", "error": "Invalid target domain"}

        try:
            # Build tasks with proper context chaining
            self._emit("INFO", "SYSTEM", "📋 Initializing tasks...", "init")

            task_passive = create_passive_recon_task(self.target)
            task_active = create_active_recon_task(self.target, task_passive)
            task_report = create_report_task(self.target, task_passive, task_active)

            # Configure agents and tasks based on scan mode
            if self.scan_mode == "passive":
                agents = [passive_recon_agent]
                tasks = [task_passive]
            elif self.scan_mode == "quick":
                agents = [active_recon_agent, report_agent]
                tasks = [task_active, task_report]
            else:  # full
                agents = [passive_recon_agent, active_recon_agent, report_agent]
                tasks = [task_passive, task_active, task_report]

            self._emit("INFO", "CREW", f"🤖 Assembling crew with {len(agents)} agents...", "init")

            # Memory requires LLM structured-output support (json_schema response_format).
            # DeepSeek does not support this format → triggers 400 errors.
            # Data flow between agents is already handled via task context=[...] chaining,
            # so crew-level memory is not needed and is disabled here.
            crew_kwargs = {
                "agents": agents,
                "tasks": tasks,
                "process": Process.sequential,
                "memory": False,
                "verbose": True,
                "output_log_file": f"outputs/logs/crew_run_{start_time.strftime('%Y%m%d_%H%M%S')}.log",
            }

            crew = Crew(**crew_kwargs)

            self._emit("INFO", "CREW", "▶️  Crew kickoff initiated...", "start")

            # Execute
            result = crew.kickoff(inputs={"target": self.target})

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            self._emit(
                "SUCCESS", "CREW",
                f"✅ Scan completed in {duration:.0f}s",
                "complete"
            )

            # Collect output file paths
            output_files = {
                "passive_json": "outputs/sessions/findings_passive.json",
                "active_json": "outputs/sessions/findings_active.json",
                "report_md": "outputs/reports/attack_surface_report.md",
                "report_html": "outputs/reports/attack_surface_report.html",
                "report_pdf": "outputs/reports/attack_surface_report.pdf",
            }

            # Count findings if available
            stats = self._gather_stats(output_files)

            return {
                "status": "completed",
                "target": self.target,
                "scan_mode": self.scan_mode,
                "duration_seconds": duration,
                "result": str(result),
                "files": output_files,
                "statistics": stats,
                # Flatten for easy UI access
                **output_files,
                **stats,
            }

        except KeyboardInterrupt:
            self._emit("WARN", "SYSTEM", "⚠️ Scan interrupted by user", "interrupted")
            return {
                "status": "interrupted",
                "target": self.target,
                "message": "Scan was interrupted. Partial results may be available.",
            }
        except Exception as e:
            self._emit("ERROR", "SYSTEM", f"❌ Scan failed: {str(e)}", "error")
            logger.exception("Crew run failed")
            return {
                "status": "error",
                "target": self.target,
                "error": str(e),
            }

    def _gather_stats(self, output_files: dict) -> dict:
        """Read output files and gather statistics from compiled findings."""
        stats = {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "subdomains_count": 0,
            "open_ports_count": 0,
            "all_findings_list": [],
            "category_breakdown": {},
        }

        passive_path = output_files.get("passive_json", "")
        active_path = output_files.get("active_json", "")

        passive_data = {}
        active_data = {}

        try:
            if Path(passive_path).exists():
                with open(passive_path, "r", encoding="utf-8") as f:
                    passive_data = json.load(f)
                stats["subdomains_count"] = len(passive_data.get("subdomains", []))
        except Exception:
            pass

        try:
            if Path(active_path).exists():
                with open(active_path, "r", encoding="utf-8") as f:
                    active_data = json.load(f)
                open_ports = active_data.get("open_ports", {})
                port_count = sum(
                    len(ports) for ports in open_ports.values()
                    if isinstance(ports, dict)
                )
                stats["open_ports_count"] = port_count
        except Exception:
            pass

        # Compile findings inline (mirrors compile_tool logic) to get accurate severity counts
        try:
            all_findings = []
            category_breakdown = {}

            # Services from active open_ports
            for host, ports in active_data.get("open_ports", {}).items():
                if isinstance(ports, dict):
                    for port_num, port_info in ports.items():
                        if isinstance(port_info, dict):
                            all_findings.append({
                                "category": "network_service",
                                "severity": "Info",
                                "title": (
                                    f"{port_info.get('service','unknown').upper()} "
                                    f"on port {port_num}"
                                ),
                            })

            # SSL findings
            for finding in active_data.get("ssl_findings", []):
                if isinstance(finding, dict):
                    sev = (
                        "Critical" if (finding.get("cert_expiry_days") or 9999) < 0
                        else "High" if (
                            "1.0" in str(finding.get("tls_versions", []))
                            or (finding.get("cert_expiry_days") or 9999) < 30
                        )
                        else "Medium"
                    )
                    all_findings.append({
                        "category": "ssl_tls",
                        "severity": sev,
                        "title": f"SSL/TLS Issue: {finding.get('issue', '')}",
                    })

            # Missing security headers
            for host, headers in active_data.get("missing_headers", {}).items():
                if isinstance(headers, list):
                    for header in headers:
                        sev = (
                            "High" if header in [
                                "Strict-Transport-Security",
                                "Content-Security-Policy",
                            ]
                            else "Medium"
                        )
                        all_findings.append({
                            "category": "security_headers",
                            "severity": sev,
                            "title": f"Missing Security Header: {header}",
                        })

            # WAF absent
            for host, waf_info in active_data.get("waf_info", {}).items():
                if isinstance(waf_info, dict) and not waf_info.get("detected", False):
                    all_findings.append({
                        "category": "misconfiguration",
                        "severity": "Medium",
                        "title": f"No WAF Detected on {host}",
                    })

            # Dangerous HTTP methods
            for host, methods in active_data.get("dangerous_methods", {}).items():
                if isinstance(methods, list):
                    for method in methods:
                        all_findings.append({
                            "category": "misconfiguration",
                            "severity": "High" if method in ["PUT", "DELETE", "DEBUG"] else "Medium",
                            "title": f"Dangerous HTTP Method Enabled: {method}",
                        })

            # Cloud assets (only verified publics)
            cloud = active_data.get("cloud_assets", {})
            for bucket in (
                cloud.get("s3_buckets", []) + cloud.get("gcs_buckets", [])
            ):
                status = bucket.get("status") if isinstance(bucket, dict) else None
                if status == "PUBLIC":
                    all_findings.append({
                        "category": "cloud_misconfiguration",
                        "severity": "Critical",
                        "title": f"Public Cloud Bucket: {bucket.get('name', 'unknown')}",
                    })

            # OSINT: emails
            emails = passive_data.get("osint_emails", [])
            if emails:
                all_findings.append({
                    "category": "information_disclosure",
                    "severity": "Low",
                    "title": f"Email Addresses Discovered ({len(emails)})",
                })

            # Google dork hits
            dork_hits = [
                d for d in passive_data.get("google_dorks", [])
                if isinstance(d, dict) and d.get("count", 0) > 0
            ]
            if dork_hits:
                all_findings.append({
                    "category": "information_disclosure",
                    "severity": "Medium",
                    "title": f"Google Dork Hits Found ({len(dork_hits)} queries)",
                })

            # Count severity
            sev_map = {
                "Critical": "critical_count",
                "High": "high_count",
                "Medium": "medium_count",
                "Low": "low_count",
                "Info": "info_count",
            }
            for f in all_findings:
                sev = f.get("severity", "Info")
                key = sev_map.get(sev, "info_count")
                stats[key] = stats.get(key, 0) + 1
                cat = f.get("category", "other")
                category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

            stats["total_findings"] = len(all_findings)
            stats["all_findings_list"] = [f["title"] for f in all_findings[:50]]
            stats["category_breakdown"] = category_breakdown

        except Exception:
            pass

        return stats
