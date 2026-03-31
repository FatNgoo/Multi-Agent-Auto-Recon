#!/usr/bin/env python3
# main.py — CLI Entry Point for Multi-Agent Recon System
"""
Multi-Agent Reconnaissance & Attack Surface Reporting System
Usage:
    python main.py --target example.com
    python main.py --target example.com --mode passive
    python main.py --target example.com --mode full --output-dir ./outputs
    python main.py --list-sessions
"""

import argparse
import io
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Fix Windows Unicode encoding (cp1252 → utf-8)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Load environment variables before importing modules that need them
load_dotenv()

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


def print_banner():
    """Print ASCII art banner."""
    banner = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🛡️  MULTI-AGENT RECON SYSTEM                               ║
║   Automated Attack Surface Reconnaissance                    ║
║                                                              ║
║   Framework: CrewAI  |  LLM: DeepSeek                        ║
║   Tools: 35+         |  Agents: 3                            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def validate_environment():
    """Check required environment variables and dependencies."""
    issues = []
    warnings = []

    # Required
    if not os.getenv("DEEPSEEK_API_KEY"):
        issues.append("❌ DEEPSEEK_API_KEY not set in .env")

    # Optional but recommended
    if not os.getenv("SHODAN_API_KEY"):
        warnings.append("⚠️  SHODAN_API_KEY not set — Shodan scan will be skipped")
    if not os.getenv("NVD_API_KEY"):
        warnings.append("⚠️  NVD_API_KEY not set — CVE lookup will be rate limited (slower)")
    if not os.getenv("URLSCAN_API_KEY"):
        warnings.append("⚠️  URLSCAN_API_KEY not set — URLScan will be skipped")

    # Check nmap availability
    import shutil
    if not shutil.which("nmap"):
        warnings.append("⚠️  nmap not found — Port scanning may be limited")

    for w in warnings:
        print(w)

    if issues:
        for issue in issues:
            print(issue)
        print("\n💡 Copy .env.example to .env and fill in your API keys.")
        return False

    return True


def list_sessions():
    """List all saved scan sessions."""
    from memory.session_manager import SessionManager
    sm = SessionManager()
    sessions = sm.list_sessions()

    if not sessions:
        print("No saved sessions found.")
        return

    print(f"\n{'Target':<30} {'Saved At':<25} {'File'}")
    print("-" * 80)
    for s in sessions:
        print(f"{s['target']:<30} {s['saved_at'][:19]:<25} {s['file']}")


def run_scan(args):
    """Execute the recon scan."""
    from crew.recon_crew import ReconCrew
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn

    console = Console()
    target = args.target
    mode = args.mode
    output_dir = args.output_dir

    # Override output paths
    if output_dir != "./outputs":
        os.environ["OUTPUT_DIR"] = output_dir
        os.makedirs(f"{output_dir}/sessions", exist_ok=True)
        os.makedirs(f"{output_dir}/reports", exist_ok=True)
        os.makedirs(f"{output_dir}/logs", exist_ok=True)

    console.print(f"\n[bold cyan]🎯 Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]📋 Mode:[/bold cyan] {mode}")
    console.print(f"[bold cyan]📁 Output:[/bold cyan] {output_dir}")
    console.print(f"[bold cyan]⏰ Started:[/bold cyan] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print("\n" + "─" * 60)

    # Check resume
    if not args.no_resume:
        from memory.session_manager import SessionManager
        sm = SessionManager()
        resume_info = sm.check_resume(target)
        if resume_info["can_resume"]:
            console.print(
                f"[yellow]📂 Found existing session for {target}.[/yellow]\n"
                f"   Passive done: {'✓' if resume_info['passive_done'] else '✗'}\n"
                f"   Active done: {'✓' if resume_info['active_done'] else '✗'}\n"
                f"   Will start from: [bold]{resume_info['start_from']}[/bold]"
            )
            if not args.force:
                response = input("\nResume from previous session? [Y/n]: ").strip().lower()
                if response not in ("n", "no"):
                    mode = resume_info["start_from"]
                    if mode == "report":
                        mode = "report_only"

    # Event logger for CLI
    def log_event(event: dict):
        level = event.get("level", "INFO")
        msg = event.get("message", "")
        agent = event.get("agent", "")

        level_styles = {
            "INFO": "dim white",
            "SUCCESS": "bold green",
            "WARN": "yellow",
            "ERROR": "bold red",
            "TOOL": "cyan",
        }
        style = level_styles.get(level, "white")
        time_str = event.get("timestamp", "")[-8:][:8]
        console.print(f"[dim]{time_str}[/dim] [[{style}]{level:<7}[/{style}]] [{agent}] {msg}")

    # Create and run crew
    crew = ReconCrew(
        target=target,
        event_callback=log_event,
        scan_mode=mode,
        enable_shodan=not args.no_shodan,
        enable_dorks=not args.no_dorks,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("[cyan]Running recon...", total=None)
        result = crew.run()
        progress.stop_task(task_id)

    # Display results
    console.print("\n" + "─" * 60)

    if result.get("status") == "completed":
        console.print("[bold green]✅ SCAN COMPLETED SUCCESSFULLY[/bold green]")
        console.print(f"\n[bold]Duration:[/bold] {result.get('duration_seconds', 0):.0f} seconds")

        stats = result.get("statistics", {})
        if stats.get("total_findings"):
            console.print(f"\n[bold]📊 Findings Summary:[/bold]")
            console.print(f"   Total: {stats.get('total_findings', 0)}")
            console.print(f"   Critical: [bold red]{stats.get('critical_count', 0)}[/bold red]")
            console.print(f"   High: [orange3]{stats.get('high_count', 0)}[/orange3]")
            console.print(f"   Medium: [yellow]{stats.get('medium_count', 0)}[/yellow]")
            console.print(f"   Subdomains: {stats.get('subdomains_count', 0)}")
            console.print(f"   Open Ports: {stats.get('open_ports_count', 0)}")

        console.print("\n[bold]📁 Output Files:[/bold]")
        files = result.get("files", {})
        for name, path in files.items():
            if path and Path(path).exists():
                console.print(f"   ✓ {name}: [link={path}]{path}[/link]")
            else:
                console.print(f"   ✗ {name}: not generated")

    elif result.get("status") == "error":
        console.print(f"[bold red]❌ SCAN FAILED[/bold red]: {result.get('error')}")
        sys.exit(1)
    else:
        console.print(f"[yellow]⚠️  Scan status: {result.get('status')}[/yellow]")

    # Save result summary
    summary_path = f"{output_dir}/scan_summary_{target.replace('.', '_')}.json"
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            # Remove non-serializable items
            clean_result = {k: v for k, v in result.items() if isinstance(v, (str, int, float, dict, list, bool, type(None)))}
            json.dump(clean_result, f, ensure_ascii=False, indent=2)
        console.print(f"\n[dim]Summary saved: {summary_path}[/dim]")
    except Exception:
        pass

    return result


def main():
    """Main CLI entry point."""
    print_banner()

    parser = argparse.ArgumentParser(
        description="Multi-Agent Recon System — Automated Attack Surface Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target scanme.nmap.org
  python main.py --target example.com --mode passive
  python main.py --target example.com --mode full --output-dir ./my_output
  python main.py --list-sessions
  python main.py --target example.com --force --no-resume
        """,
    )

    parser.add_argument(
        "--target", "-t",
        type=str,
        help="Target domain to scan (e.g., example.com)",
    )
    parser.add_argument(
        "--mode", "-m",
        type=str,
        choices=["full", "passive", "quick"],
        default="full",
        help="Scan mode: full (passive+active+report), passive, quick (default: full)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="./outputs",
        help="Output directory (default: ./outputs)",
    )
    parser.add_argument(
        "--list-sessions", "-l",
        action="store_true",
        help="List all saved scan sessions",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Don't resume from previous session",
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force start (skip resume prompt)",
    )
    parser.add_argument(
        "--no-shodan",
        action="store_true",
        help="Skip Shodan scan",
    )
    parser.add_argument(
        "--no-dorks",
        action="store_true",
        help="Skip Google dorking",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate environment and exit",
    )

    args = parser.parse_args()

    # Handle --list-sessions
    if args.list_sessions:
        list_sessions()
        return

    # Handle --validate
    if args.validate:
        ok = validate_environment()
        sys.exit(0 if ok else 1)

    # Require target for scanning
    if not args.target:
        parser.print_help()
        print("\n❌ Error: --target is required for scanning")
        sys.exit(1)

    # Validate environment
    if not validate_environment():
        print("\n⚠️  Continuing with limited functionality...")

    # Run scan
    run_scan(args)


if __name__ == "__main__":
    main()
