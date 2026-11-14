"""Per-session taint state and where it is stored.

Hooks run as a fresh process per tool call, so state must live on disk. Each session is one
small JSON file guarded by a lock file. Private data is never stored, only salted hashes.
"""

from __future__ import annotations

import json
import os
import re
import secrets as _secrets
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

MAX_EVENTS = 50
MAX_FINGERPRINTS = 20000
MAX_HOSTS = 2000


def default_home() -> Path:
    return Path(os.environ.get("TRIFECTA_GUARD_HOME") or Path.home() / ".trifecta-guard")


@dataclass
class SessionState:
    session_id: str
    salt: str = field(default_factory=lambda: _secrets.token_hex(16))
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)
    tainted: bool = False
    compromised: bool = False
    events: list[dict] = field(default_factory=list)
    untrusted_hosts: list[str] = field(default_factory=list)
    trusted_hosts: list[str] = field(default_factory=list)
    private_fps: list[str] = field(default_factory=list)

    # --- mutation helpers -----------------------------------------------------------------
    def add_event(self, **event) -> None:
        event.setdefault("at", round(time.time(), 3))
        self.events.append(event)
        del self.events[:-MAX_EVENTS]

    def add_hosts(self, which: str, hosts: set[str] | list[str]) -> None:
        lst: list[str] = getattr(self, which)
        known = set(lst)
        for h in sorted(hosts):
            if h not in known:
                lst.append(h)
                known.add(h)
        del lst[:-MAX_HOSTS]

    def add_fingerprints(self, fps: set[str]) -> None:
        known = set(self.private_fps)
        self.private_fps.extend(sorted(fps - known))
        del self.private_fps[:-MAX_FINGERPRINTS]

    @property
    def level(self) -> str:
        return "compromised" if self.compromised else "tainted" if self.tainted else "clean"

    def public_view(self) -> dict:
        d = asdict(self)
        d.pop("salt")
        d["private_fingerprints"] = len(d.pop("private_fps"))
        d["level"] = self.level
        return d


class MemoryStore:
    """In-process store (library use, tests, the MCP proxy without --state-dir)."""

    def __init__(self) -> None:
        self._data: dict[str, SessionState] = {}

    @contextmanager
    def session(self, session_id: str) -> Iterator[SessionState]:
        st = self._data.get(session_id) or SessionState(session_id)
        yield st
        st.updated = time.time()
        self._data[session_id] = st

    def peek(self, session_id: str) -> SessionState | None:
        return self._data.get(session_id)

    def reset(self, session_id: str) -> None:
        self._data.pop(session_id, None)


_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]")


class FileStore:
    """One JSON file per session under ``<home>/sessions``; safe across concurrent processes."""

    def __init__(self, home: str | os.PathLike | None = None, lock_timeout: float = 5.0) -> None:
        self.root = Path(home) if home else default_home()
        self.dir = self.root / "sessions"
        self.lock_timeout = lock_timeout

    def _path(self, session_id: str) -> Path:
        sid = _SAFE_ID.sub("_", session_id)[:128] or "default"
        return self.dir / f"{sid}.json"

    @contextmanager
    def _lock(self, path: Path) -> Iterator[None]:
        lock = path.with_suffix(".lock")
        deadline = time.monotonic() + self.lock_timeout
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                break
            except FileExistsError:
                try:  # break locks left behind by a crashed process
                    if time.time() - lock.stat().st_mtime > max(30.0, self.lock_timeout * 2):
                        lock.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"could not lock {path}")
                time.sleep(0.01)
        try:
            yield
        finally:
            lock.unlink(missing_ok=True)

    def _read(self, path: Path, session_id: str) -> SessionState:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return SessionState(**{k: v for k, v in raw.items() if k in SessionState.__dataclass_fields__})
        except FileNotFoundError:
            return SessionState(session_id)
        except (json.JSONDecodeError, TypeError):
            # A corrupt state file must not silently reset taint: start tainted.
            st = SessionState(session_id, tainted=True)
            st.add_event(kind="state_corrupt", note="state file unreadable; session assumed tainted")
            return st

    @contextmanager
    def session(self, session_id: str) -> Iterator[SessionState]:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        path = self._path(session_id)
        with self._lock(path):
            st = self._read(path, session_id)
            yield st
            st.updated = time.time()
            fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(asdict(st), fh)
            os.replace(tmp, path)

    def peek(self, session_id: str) -> SessionState | None:
        path = self._path(session_id)
        return self._read(path, session_id) if path.exists() else None

    def reset(self, session_id: str) -> None:
        self._path(session_id).unlink(missing_ok=True)

    def list(self) -> list[SessionState]:
        if not self.dir.exists():
            return []
        out = []
        for p in sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            out.append(self._read(p, p.stem))
        return out
