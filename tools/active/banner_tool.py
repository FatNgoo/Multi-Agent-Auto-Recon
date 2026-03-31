# tools/active/banner_tool.py
import json
import socket
from crewai.tools import tool

COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995,
                3306, 3389, 5432, 6379, 8080, 8443, 27017]


@tool("Banner Grabber")
def banner_grabber(input_json: str) -> str:
    """
    Grab raw TCP/UDP banners từ open ports. Xác định service versions từ banners.
    Input: JSON string {"host": "1.2.3.4", "ports": [80, 443, 22]}
    Nếu ports không được cung cấp, sẽ quét danh sách cổng phổ biến.
    """
    try:
        import json as _json
        try:
            params = _json.loads(input_json)
        except Exception:
            params = {"host": input_json.strip()}

        host = params.get("host", "")
        ports = params.get("ports", COMMON_PORTS)
        if isinstance(ports, str):
            ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]

        if not host:
            return json.dumps({"error": "No host specified"})

        banners = []
        for port in ports[:20]:  # Limit to 20 ports
            banner_text = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(8)
                result = sock.connect_ex((host, int(port)))
                if result == 0:
                    # Try to receive banner
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                        banner_bytes = sock.recv(1024)
                        banner_text = banner_bytes.decode("utf-8", errors="replace").strip()[:300]
                    except Exception:
                        try:
                            banner_bytes = sock.recv(512)
                            banner_text = banner_bytes.decode("utf-8", errors="replace").strip()[:300]
                        except Exception:
                            banner_text = "(connection open, no banner)"

                    banners.append({
                        "host": host,
                        "port": port,
                        "open": True,
                        "banner": banner_text,
                    })
                sock.close()
            except Exception:
                pass

        return json.dumps({
            "host": host,
            "ports_checked": len(ports),
            "open_ports": len(banners),
            "banners": banners,
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})
