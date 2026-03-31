# tools/active/nmap_tool.py
import json
import shutil
import nmap
from crewai.tools import tool


@tool("Nmap Port Scanner")
def nmap_port_scan(input_json: str) -> str:
    """
    Quét ports và dịch vụ bằng Nmap. Lấy thông tin service version, banner.
    Input: JSON string {"host": "1.2.3.4", "ports": "1-1000", "scan_type": "version"}
    scan_type options: "version" (default), "quick", "udp"
    """
    if not shutil.which("nmap"):
        return json.dumps({
            "error": "nmap not found in PATH. Install nmap first.",
            "install": "https://nmap.org/download.html"
        })

    try:
        import json as _json
        try:
            params = _json.loads(input_json)
        except Exception:
            # Treat as plain host string
            params = {"host": input_json.strip()}

        host = params.get("host", "")
        ports = params.get("ports", "80,443,22,21,25,53,110,143,8080,8443")
        scan_type = params.get("scan_type", "version")

        if not host:
            return json.dumps({"error": "No host specified"})

        nm = nmap.PortScanner()

        if scan_type == "quick":
            args = "-T4 --open -F"
        elif scan_type == "udp":
            args = "-sU -T3 --open -p 53,67,68,161,162,500"
            ports = None
        else:  # version
            args = "-sV -T4 --open"

        scan_args = args + (f" -p {ports}" if ports and scan_type != "udp" else "")
        nm.scan(hosts=host, arguments=scan_args, timeout=120)

        results = []
        for scanned_host in nm.all_hosts():
            host_result = {
                "host": scanned_host,
                "hostname": nm[scanned_host].hostname(),
                "state": nm[scanned_host].state(),
                "ports": [],
                "os_guess": "",
            }

            for proto in nm[scanned_host].all_protocols():
                for port_num in sorted(nm[scanned_host][proto].keys()):
                    port_data = nm[scanned_host][proto][port_num]
                    host_result["ports"].append({
                        "port": port_num,
                        "protocol": proto,
                        "state": port_data.get("state", ""),
                        "service": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                    })

            results.append(host_result)

        return json.dumps({"scan_results": results}, ensure_ascii=False, indent=2)

    except nmap.PortScannerError as e:
        return json.dumps({"error": f"Nmap error: {str(e)}"})
    except Exception as e:
        return json.dumps({"error": str(e)})
