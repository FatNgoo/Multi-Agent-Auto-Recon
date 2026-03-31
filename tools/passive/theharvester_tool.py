# tools/passive/theharvester_tool.py
import json
import subprocess
import shutil
import tempfile
import os
from crewai.tools import tool


@tool("TheHarvester OSINT Runner")
def theharvester_runner(domain: str) -> str:
    """
    Chạy theHarvester để thu thập emails, hosts, URLs từ nhiều nguồn OSINT.
    Thu thập thông tin nhân viên, địa chỉ email và subdomain từ public sources.
    Input: tên miền (ví dụ: example.com)
    """
    harvester_path = shutil.which("theHarvester") or shutil.which("theharvester")
    if not harvester_path:
        # Fallback: try python -m theHarvester
        try:
            test = subprocess.run(
                ["python", "-m", "theHarvester", "--help"],
                capture_output=True, timeout=5
            )
            if test.returncode != 0:
                return json.dumps({
                    "status": "unavailable",
                    "error": "theHarvester not installed. Install with: pip install theHarvester",
                    "fallback": "Using manual OSINT gathering",
                    "domain": domain
                })
        except Exception:
            return json.dumps({
                "status": "unavailable",
                "error": "theHarvester not found in PATH",
                "domain": domain
            })

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        cmd = [
            harvester_path, "-d", domain,
            "-b", "bing,duckduckgo,google,yahoo",
            "-f", tmp_path,
            "-l", "100",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )

        emails = []
        hosts = []

        # Parse stdout for basic results
        stdout = result.stdout + result.stderr
        for line in stdout.splitlines():
            line = line.strip()
            if "@" in line and domain in line and not line.startswith("["):
                emails.append(line)
            elif domain in line and "." in line and not line.startswith("["):
                hosts.append(line)

        # Try parse JSON output
        try:
            if os.path.exists(tmp_path + ".json"):
                with open(tmp_path + ".json", "r") as f:
                    json_data = json.load(f)
                    emails = list(set(emails + json_data.get("emails", [])))
                    hosts = list(set(hosts + json_data.get("hosts", [])))
        except Exception:
            pass

        # Cleanup
        for p in [tmp_path, tmp_path + ".json", tmp_path + ".xml"]:
            try:
                os.remove(p)
            except Exception:
                pass

        return json.dumps({
            "domain": domain,
            "emails_found": list(set(emails))[:50],
            "hosts_found": list(set(hosts))[:50],
            "total_emails": len(set(emails)),
            "total_hosts": len(set(hosts)),
        }, ensure_ascii=False, indent=2)

    except subprocess.TimeoutExpired:
        return json.dumps({"error": "theHarvester timed out (120s)", "domain": domain})
    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
