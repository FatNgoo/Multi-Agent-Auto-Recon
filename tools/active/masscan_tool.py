# tools/active/masscan_tool.py
import json
import shutil
import subprocess
import tempfile
import os
import re
from crewai.tools import tool


@tool("Masscan Fast Port Scanner")
def masscan_wrapper(input_json: str) -> str:
    """
    Quét port nhanh bằng masscan (faster than nmap for large ranges).
    Input: JSON string {"host": "1.2.3.4", "ports": "1-65535", "rate": 1000}
    """
    if not shutil.which("masscan"):
        # Fallback: use nmap for fast scan
        return json.dumps({
            "status": "masscan_unavailable",
            "note": "masscan not found. Using nmap quick scan as fallback.",
            "suggestion": "Install masscan from https://github.com/robertdavidgraham/masscan"
        })

    try:
        import json as _json
        try:
            params = _json.loads(input_json)
        except Exception:
            params = {"host": input_json.strip()}

        host = params.get("host", "")
        ports = params.get("ports", "1-10000")
        rate = min(int(params.get("rate", 1000)), 5000)  # Cap at 5000 to avoid disruption

        if not host:
            return json.dumps({"error": "No host specified"})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmp_path = f.name

        cmd = [
            "masscan", host,
            "-p", ports,
            "--rate", str(rate),
            "-oJ", tmp_path,
            "--wait", "2",
        ]

        subprocess.run(cmd, capture_output=True, timeout=120, check=False)

        open_ports = []
        if os.path.exists(tmp_path):
            with open(tmp_path, "r") as f:
                content = f.read().strip()
            if content:
                # masscan JSON may have trailing comma issues
                content = content.rstrip(",\n") 
                if not content.startswith("["):
                    content = "[" + content + "]"
                try:
                    data = json.loads(content)
                    for entry in data:
                        for port_info in entry.get("ports", []):
                            open_ports.append({
                                "ip": entry.get("ip"),
                                "port": port_info.get("port"),
                                "proto": port_info.get("proto", "tcp"),
                                "status": port_info.get("status", "open"),
                            })
                except Exception:
                    pass
            os.remove(tmp_path)

        return json.dumps({
            "host": host,
            "ports_scanned": ports,
            "rate": rate,
            "open_ports": open_ports,
            "total_open": len(open_ports),
        }, ensure_ascii=False, indent=2)

    except subprocess.TimeoutExpired:
        return json.dumps({"error": "masscan timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})
