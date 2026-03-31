# memory/session_manager.py
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


class SessionManager:
    """
    Manages scan sessions: save/load findings between runs.
    Enables resume capability if a scan is interrupted.
    """

    SESSION_DIR = Path("outputs/sessions")

    def __init__(self):
        self.SESSION_DIR.mkdir(parents=True, exist_ok=True)

    def _session_path(self, target: str, phase: str) -> Path:
        safe_target = (
            target.replace(".", "_")
                  .replace("/", "_")
                  .replace(":", "_")
                  .replace("*", "_")
        )
        return self.SESSION_DIR / f"{safe_target}_{phase}.json"

    def save_session(self, target: str, phase: str, data: dict) -> str:
        """Save findings for a scan phase."""
        path = self._session_path(target, phase)
        payload = {
            "target": target,
            "phase": phase,
            "saved_at": datetime.now().isoformat(),
            "data": data,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return str(path)

    def load_session(self, target: str, phase: str) -> Optional[dict]:
        """Load a session if it exists, None otherwise."""
        path = self._session_path(target, phase)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
                return payload.get("data", payload)
        return None

    def session_exists(self, target: str, phase: str) -> bool:
        """Check if a session file exists."""
        return self._session_path(target, phase).exists()

    def check_resume(self, target: str) -> dict:
        """Check what phases can be resumed for a target."""
        passive_exists = self._session_path(target, "passive").exists()
        active_exists = self._session_path(target, "active").exists()

        return {
            "can_resume": passive_exists or active_exists,
            "passive_done": passive_exists,
            "active_done": active_exists,
            "start_from": (
                "report" if passive_exists and active_exists
                else "active" if passive_exists
                else "passive"
            ),
        }

    def list_sessions(self) -> list:
        """List all saved sessions."""
        sessions = []
        for f in sorted(self.SESSION_DIR.glob("*_passive.json"), reverse=True):
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    sessions.append({
                        "target": data.get("target", f.stem.replace("_passive", "")),
                        "saved_at": data.get("saved_at", ""),
                        "file": str(f),
                    })
            except Exception:
                sessions.append({
                    "target": f.stem.replace("_passive", "").replace("_", "."),
                    "saved_at": "",
                    "file": str(f),
                })
        return sessions

    def delete_session(self, target: str):
        """Delete all session files for a target."""
        for phase in ["passive", "active", "report"]:
            path = self._session_path(target, phase)
            if path.exists():
                path.unlink()
