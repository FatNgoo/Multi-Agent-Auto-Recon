# memory/context_manager.py
import json
import os
from typing import Optional


class ContextManager:
    """
    Manages context to avoid exceeding LLM token limits.
    Trims or summarizes data before injecting into agents.
    """

    MAX_TOKENS_FOR_ACTIVE = 2000
    MAX_TOKENS_FOR_REPORT = 4500

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count (1 token ≈ 4 chars)."""
        return len(text) // 4

    def trim_passive_for_active(self, passive_findings: dict) -> dict:
        """
        Extract only what the active agent needs from passive findings.
        Active agent needs: IPs, subdomains, open ports (from Shodan).
        Does NOT need: raw WHOIS text, full cert chains, all emails.
        """
        dns_records = passive_findings.get("dns_records", {})
        subdomains = passive_findings.get("subdomains", [])

        trimmed = {
            "target": passive_findings.get("target"),
            "primary_ip": (
                dns_records.get("A", [None])[0]
                if dns_records.get("A")
                else None
            ),
            "all_ips": dns_records.get("A", [])[:20],
            "top_subdomains": [
                {
                    "subdomain": s["subdomain"] if isinstance(s, dict) else s,
                    "ip": s.get("ip") if isinstance(s, dict) else None,
                }
                for s in subdomains[:25]
            ],
            "shodan_open_ports": passive_findings.get("shodan_data", {}).get("ports", []),
            "waf_hint": passive_findings.get("shodan_data", {}).get("tags", []),
            "note": (
                f"Total subdomains found: {len(subdomains)}. "
                f"Showing top 25."
            ),
        }

        # Verify token count and trim further if needed
        trimmed_json = json.dumps(trimmed)
        if self.estimate_tokens(trimmed_json) > self.MAX_TOKENS_FOR_ACTIVE:
            trimmed["top_subdomains"] = trimmed["top_subdomains"][:10]

        return trimmed

    def merge_for_report(self, passive: dict, active: dict) -> dict:
        """
        Merge passive + active findings for the report agent.
        Report agent needs: service versions (CVE), all finding categories.
        """
        merged = {
            "target": passive.get("target", active.get("target", "unknown")),
            "infrastructure_summary": {
                "total_subdomains": len(passive.get("subdomains", [])),
                "ip_ranges": passive.get("asn_info", {}).get("cidr", []),
                "registrar": passive.get("whois", {}).get("registrar"),
                "emails_found": len(passive.get("osint_emails", [])),
            },
            "services_with_versions": {},
            "security_findings": {
                "ssl_issues": active.get("ssl_findings", []),
                "missing_headers": active.get("missing_headers", {}),
                "dangerous_methods": active.get("dangerous_methods", {}),
                "waf_info": active.get("waf_info", {}),
                "cloud_assets": active.get("cloud_assets", {}),
                "discovered_paths": active.get("discovered_paths", {}),
            },
            "google_dork_hits": [
                d for d in passive.get("google_dorks", [])
                if isinstance(d, dict) and d.get("count", 0) > 0
            ],
            "interesting_historical_urls": passive.get("historical_urls", [])[:10],
        }

        # Extract versioned services
        for host, ports in active.get("open_ports", {}).items():
            if isinstance(ports, dict):
                versioned = {
                    port: {
                        "service": info.get("service"),
                        "version": info.get("version"),
                        "product": info.get("product"),
                    }
                    for port, info in ports.items()
                    if isinstance(info, dict) and info.get("version")
                }
                if versioned:
                    merged["services_with_versions"][host] = versioned

        return merged

    def summarize_with_llm(
        self,
        data: dict,
        purpose: str,
        max_words: int = 500,
    ) -> Optional[str]:
        """
        Call DeepSeek to summarize if data is too large.
        purpose: "active_recon" or "report_writing"
        """
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            return None

        try:
            from openai import OpenAI
            client = OpenAI(
                api_key=api_key,
                base_url="https://api.deepseek.com",
            )

            prompt = (
                f"Summarize the following security scan data for {purpose}.\n"
                f"Focus on: IP addresses, open ports, service versions, "
                f"and key security issues.\n"
                f"Maximum {max_words} words. Return as JSON.\n\n"
                f"Data:\n{json.dumps(data)[:3000]}"
            )

            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=800,
                temperature=0.0,
            )

            return response.choices[0].message.content

        except Exception:
            return None
