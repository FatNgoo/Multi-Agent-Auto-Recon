"""
Pytest configuration and shared fixtures for multi_agent_recon tests.
"""
import pytest
import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()


# ─── SAMPLE DATA FIXTURES ─────────────────────────────────────────────────────

@pytest.fixture
def sample_target():
    return "scanme.nmap.org"


@pytest.fixture
def sample_passive_findings():
    fixtures_dir = Path(__file__).parent / "fixtures"
    with open(fixtures_dir / "sample_passive.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def sample_active_findings():
    fixtures_dir = Path(__file__).parent / "fixtures"
    with open(fixtures_dir / "sample_active.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def sample_compiled_findings(sample_passive_findings, sample_active_findings):
    return {
        "target": "scanme.nmap.org",
        "passive": sample_passive_findings,
        "active": sample_active_findings,
        "services": [
            {"port": 80, "proto": "tcp", "service": "http", "version": "Apache/2.4.58"},
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9"},
        ],
        "web_findings": [
            {"url": "http://scanme.nmap.org/robots.txt", "status": 200},
        ],
        "severity_stats": {
            "Critical": 0, "High": 2, "Medium": 4, "Low": 3, "Info": 5
        },
    }


@pytest.fixture
def output_dir(tmp_path):
    """Temporary output directory for tests."""
    (tmp_path / "reports").mkdir()
    (tmp_path / "sessions").mkdir()
    return tmp_path


@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    """Provide dummy API keys so tests don't need real credentials."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-dummy-key-for-testing-only")
    monkeypatch.setenv("SHODAN_API_KEY", "dummy_shodan_key")
    monkeypatch.setenv("NVD_API_KEY", "dummy-nvd-key")
