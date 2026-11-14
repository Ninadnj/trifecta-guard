"""Policy: which tools read untrusted/private data, which can send data out, and what to do."""

from __future__ import annotations

import copy
import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlsplit

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10
    import tomli as tomllib  # type: ignore[no-redef]

ACTIONS = ("allow", "ask", "deny")
POLICY_FILENAME = ".trifecta-guard.toml"


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _default_dict() -> dict:
    text = resources.files("trifecta_guard").joinpath("default_policy.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


@dataclass
class Policy:
    data: dict = field(default_factory=_default_dict)
    source: str = "default"

    # --- construction ---------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | os.PathLike | None = None, cwd: str | None = None) -> "Policy":
        """Defaults, overlaid with (in order) the first file found:
        ``path`` → ``$TRIFECTA_GUARD_POLICY`` → ``<cwd>/.trifecta-guard.toml``."""
        candidates = [path, os.environ.get("TRIFECTA_GUARD_POLICY")]
        if cwd:
            candidates.append(os.path.join(cwd, POLICY_FILENAME))
        base = _default_dict()
        for c in candidates:
            if c and os.path.isfile(c):
                with open(c, "rb") as fh:
                    pol = cls(_deep_merge(base, tomllib.load(fh)), source=str(c))
                pol.validate()
                return pol
        return cls(base)

    @classmethod
    def from_dict(cls, override: dict) -> "Policy":
        pol = cls(_deep_merge(_default_dict(), override), source="dict")
        pol.validate()
        return pol

    def validate(self) -> None:
        for key, val in self.data.get("gate", {}).items():
            if val not in ACTIONS:
                raise ValueError(f"gate.{key} must be one of {ACTIONS}, got {val!r}")
        if self.data["output"]["on_injection"] not in ("redact", "quarantine", "warn"):
            raise ValueError("output.on_injection must be redact | quarantine | warn")
        if self.data["runtime"]["fail_mode"] not in ACTIONS:
            raise ValueError(f"runtime.fail_mode must be one of {ACTIONS}")

    # --- accessors ------------------------------------------------------------------------
    def get(self, section: str, key: str) -> Any:
        return self.data[section][key]

    def gate(self, key: str) -> str:
        return self.data["gate"][key]

    @property
    def threshold(self) -> float:
        return float(self.data["detector"]["threshold"])

    def host_allowed(self, host: str) -> bool:
        host = host.lower()
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.data["hosts"]["allow"])

    def _match(self, name: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(name, p) for p in patterns)

    def path_is(self, kind: str, path: str) -> bool:
        p = os.path.expanduser(path).replace("\\", "/")
        if not p.startswith("/"):
            p = "/" + p
        return any(fnmatch.fnmatchcase(p, pat) or fnmatch.fnmatchcase(p.lower(), pat.lower())
                   for pat in self.data["paths"][kind])

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2)

    # --- classification -------------------------------------------------------------------
    def classify(self, tool: str, args: dict | None) -> "ToolRole":
        return classify(self, tool, args or {})


# --- tool classification ------------------------------------------------------------------

_URL = re.compile(r"https?://[^\s'\"<>()\[\]{}|\\^`]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_SCP_HOST = re.compile(r"\b(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+):(?:/|~|\w)")
_SSH_HOST = re.compile(r"\b(?:ssh|sftp|ftp|telnet|nc|ncat|netcat)\s+(?:-\S+\s+)*(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+)")

NET_CMD = re.compile(
    r"(?:^|[\s;&|(`$])(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|http|https|httpie|xh|aria2c|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|/dev/(?:tcp|udp)/|\bgit\s+push\b|\bgh\s+(?:api|gist\s+create|"
    r"issue\s+(?:create|comment)|pr\s+(?:create|comment)|release\s+create)\b|"
    r"\b(?:python3?|node|ruby|perl|php)\b[^|;&]*?(?:requests\.|urllib|http\.client|socket\.|fetch\(|https?\.request|"
    r"Net::HTTP|LWP|curl_)",
    re.IGNORECASE,
)
FETCH_CMD = re.compile(
    r"(?:^|[\s;&|(`$])(?:curl|wget|http|https|httpie|xh|lynx|w3m)\b|\bgh\s+(?:issue|pr)\s+(?:view|list)\b|"
    r"\bgh\s+api\b|\bgit\s+(?:clone|pull|fetch)\b",
    re.IGNORECASE,
)
_SENDS_DATA = re.compile(
    r"\s(?:-d|--data(?:-\w+)?|-F|--form|-T|--upload-file|--json|-X\s*(?:POST|PUT|PATCH))\b|\s@[\w./~-]+|<\s*[\w./~-]+|"
    r"\b(?:scp|rsync|sftp|git\s+push|nc|ncat|netcat)\b|/dev/(?:tcp|udp)/|\bgh\s+(?:api|gist|issue|pr|release)\b|"
    r"\|\s*(?:curl|nc|ncat|ssh)\b|\$\(|`",
    re.IGNORECASE,
)
REMOTE_EXEC = re.compile(
    r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|"
    r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n;&]*\|\s*(?:python3?|node|ruby|perl|php|iex)\b|"
    r"\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b|\b(?:pip3?|uv\s+pip|pipx)\s+install\s+(?:git\+)?https?://|"
    r"\bnpx\s+(?:-y\s+)?(?:https?://|github:)",
    re.IGNORECASE,
)
_ENV_DUMP = re.compile(r"(?:^|[\s;&|])(?:printenv|env|set|export\s+-p)\s*(?:$|[;&|>])|security\s+find-(?:generic|internet)-password|"
                       r"\bgh\s+auth\s+token\b|\baws\s+configure\s+(?:get|export)", re.IGNORECASE)
_WRITE_CMD = re.compile(r"(?:>>?|\btee\b|\bsed\s+-i|\bcp\b|\bmv\b|\bln\b|\bchmod\b|\bperl\s+-pi)", re.IGNORECASE)
_PATHISH = re.compile(r"(?:~|\.{0,2})?/?[\w.@-]+(?:/[\w.@-]+)+|\.[\w.-]+")

DEST_KEYS = {"url", "uri", "endpoint", "to", "recipient", "recipients", "cc", "bcc", "email", "channel",
             "webhook", "webhook_url", "host", "address", "target", "destination", "repo", "repository"}


def string_leaves(obj: Any) -> list[str]:
    out: list[str] = []

    def walk(o: Any) -> None:
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
        elif o is not None and not isinstance(o, bool):
            out.append(str(o))

    walk(obj)
    return out


def hosts_in(text: str) -> set[str]:
    hosts = set()
    for u in _URL.findall(text):
        h = urlsplit(u.rstrip(".,;:")).hostname
        if h:
            hosts.add(h.lower())
    for d in _EMAIL.findall(text):
        hosts.add(d.lower().rstrip("."))
    return hosts


def _url_carries_data(url: str) -> bool:
    parts = urlsplit(url)
    values = [v for _, v in parse_qsl(parts.query, keep_blank_values=True)]
    if sum(len(v) for v in values) >= 48 or any(len(v) >= 20 for v in values):
        return True
    if parts.fragment and len(parts.fragment) >= 20:
        return True
    return any(len(seg) >= 40 for seg in unquote_plus(parts.path).split("/"))


@dataclass
class ToolRole:
    tool: str
    untrusted: bool = False
    private: bool = False
    egress: bool = False
    protected_write: bool = False
    remote_exec: bool = False
    sends_private_path: bool = False
    destinations: list[str] = field(default_factory=list)
    payload: str = ""
    carries_data: bool = False
    notes: list[str] = field(default_factory=list)


def classify(policy: Policy, tool: str, args: dict) -> ToolRole:
    tools = policy.data["tools"]
    role = ToolRole(tool=tool)
    if policy._match(tool, tools["trusted"]):
        return role
    role.untrusted = policy._match(tool, tools["untrusted"])
    role.private = policy._match(tool, tools["private"])
    role.egress = policy._match(tool, tools["egress"])
    if tool == "WebFetch":
        # WebFetch's `prompt` goes to the fetch model, not to the remote site: only the URL leaves.
        leaves = [str(args.get("url") or "")]
    else:
        leaves = string_leaves(args)
    payload = "\n".join(leaves)

    if tool in ("Read", "NotebookRead"):
        path = str(args.get("file_path") or args.get("notebook_path") or args.get("path") or "")
        if path and policy.path_is("private", path):
            role.private = True
            role.notes.append("private path")
        if path and policy.path_is("untrusted", path):
            role.untrusted = True
    elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = str(args.get("file_path") or args.get("notebook_path") or "")
        if path and policy.path_is("protected", path):
            role.protected_write = True
            role.notes.append(f"write to protected path {path}")
    elif tool in ("Bash", "PowerShell"):
        cmd = str(args.get("command") or "")
        if NET_CMD.search(cmd):
            role.egress = True
            role.carries_data = bool(_SENDS_DATA.search(cmd)) or any(_url_carries_data(u) for u in _URL.findall(cmd))
        if FETCH_CMD.search(cmd):
            role.untrusted = True
        if REMOTE_EXEC.search(cmd):
            role.remote_exec = True
            role.notes.append("downloads and executes code")
        private_paths = [p for p in _PATHISH.findall(cmd) if policy.path_is("private", p)]
        if _ENV_DUMP.search(cmd) or private_paths:
            role.private = True
            role.notes.append("reads private data")
        if role.egress and private_paths:
            role.sends_private_path = True
            role.notes.append(f"sends private file {private_paths[0]}")
        if _WRITE_CMD.search(cmd) and any(policy.path_is("protected", p) for p in _PATHISH.findall(cmd)):
            role.protected_write = True
            role.notes.append("shell write to protected path")
        dests = hosts_in(cmd) | {m.lower() for m in _SCP_HOST.findall(cmd)} | {m.lower() for m in _SSH_HOST.findall(cmd)}
        role.destinations = sorted(dests)
        role.payload = cmd
        return role

    if role.egress:
        dests: set[str] = set()
        for k, v in (args or {}).items():
            if k.lower() in DEST_KEYS:
                vals = v if isinstance(v, list) else [v]
                for one in vals:
                    s = str(one)
                    found = hosts_in(s)
                    dests |= found or ({s.lower()} if s and len(s) < 200 else set())
        dests |= hosts_in(payload)
        role.destinations = sorted(dests)
        role.payload = payload
        urls = _URL.findall(payload)
        non_url_text = _URL.sub("", payload).strip()
        if tool == "WebFetch" or (urls and not non_url_text):
            role.carries_data = any(_url_carries_data(u) for u in urls)
        else:
            role.carries_data = bool(payload.strip())
    return role
