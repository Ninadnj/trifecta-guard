"""Append-only JSONL audit log. Records decisions, never tool payloads or private data."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .state import default_home


class AuditLog:
    def __init__(self, path: str | os.PathLike | None = None, enabled: bool = True) -> None:
        self.path = Path(path) if path else default_home() / "audit.jsonl"
        self.enabled = enabled

    def write(self, **event) -> None:
        if not self.enabled:
            return
        event = {"ts": round(time.time(), 3), **event}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        except OSError:
            pass  # auditing must never break the agent

    def tail(self, n: int = 20, session: str | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if session is None or row.get("session") == session:
                rows.append(row)
        return rows[-n:]
