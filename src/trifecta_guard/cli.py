"""Command line interface: ``trifecta-guard <command>``."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from importlib import resources

from . import __version__
from .audit import AuditLog
from .detect import HeuristicDetector
from .guard import Guard
from .policy import POLICY_FILENAME, Policy
from .state import FileStore, MemoryStore


def _cmd_scan(a: argparse.Namespace) -> int:
    if a.path in (None, "-"):
        text = sys.stdin.read()
    else:
        with open(a.path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    threshold = a.threshold if a.threshold is not None else Policy.load(a.policy, cwd=os.getcwd()).threshold
    v = HeuristicDetector(threshold=threshold).scan(text)
    if a.json:
        print(json.dumps(v.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(("INJECTION " if v.flagged else "clean     ") + v.summary())
        for f in sorted(v.findings, key=lambda f: -f.weight):
            damp = f" ({f.damped})" if f.damped else ""
            print(f"  {f.weight:4.2f} {f.rule:<34} {f.layer:<7} {f.excerpt[:90]}{damp}")
        for p in v.hidden_payloads:
            print(f"  hidden payload: {p[:200]!r}")
    return 1 if v.flagged else 0


def _cmd_hook(_: argparse.Namespace) -> int:
    from .integrations.claude_code import main

    return main()


def _cmd_proxy(a: argparse.Namespace) -> int:
    from .integrations.mcp_proxy import McpProxy

    cmd = a.command[1:] if a.command and a.command[0] == "--" else a.command
    if not cmd:
        print("usage: trifecta-guard proxy --name NAME -- <server command...>", file=sys.stderr)
        return 2
    policy = Policy.load(a.policy, cwd=os.getcwd())
    store = FileStore(a.state_dir) if (a.state_dir or a.session) else MemoryStore()
    guard = Guard(policy=policy, store=store)
    session = a.session or f"mcp-{a.name}-{uuid.uuid4().hex[:8]}"
    return McpProxy(cmd, guard, a.name, session, on_poisoned=a.on_poisoned, hard_exit=True).run()


def _cmd_install(a: argparse.Namespace) -> int:
    from .integrations import claude_code

    if a.target != "claude-code":
        print("only 'claude-code' is supported; for MCP clients see `trifecta-guard proxy --help`", file=sys.stderr)
        return 2
    if a.uninstall:
        path = claude_code.uninstall(a.scope, a.project_dir)
        print(f"removed trifecta-guard hooks from {path}")
        return 0
    path, settings = claude_code.install(a.scope, a.project_dir, dry_run=a.dry_run)
    if a.dry_run:
        print(json.dumps({"hooks": settings["hooks"]}, indent=2))
        print(f"\n(dry run: would write {path})", file=sys.stderr)
    else:
        print(f"installed trifecta-guard hooks in {path}")
        print("restart Claude Code (or open /hooks) so the hooks load.")
    return 0


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _cmd_status(a: argparse.Namespace) -> int:
    store = FileStore(a.state_dir)
    if a.session:
        st = store.peek(a.session)
        if not st:
            print(f"no state for session {a.session}")
            return 1
        print(json.dumps(st.public_view(), indent=2))
        return 0
    sessions = store.list()[: a.limit]
    if not sessions:
        print("no sessions recorded yet")
        return 0
    for st in sessions:
        last = next((e for e in reversed(st.events) if e.get("kind") == "untrusted_read"), None)
        src = f" last untrusted: {last['tool']}" if last else ""
        print(f"{_fmt_time(st.updated)}  {st.level:<11} {st.session_id}{src}")
    return 0


def _cmd_reset(a: argparse.Namespace) -> int:
    Guard(store=FileStore(a.state_dir)).reset(a.session)
    print(f"reset {a.session}")
    return 0


def _cmd_audit(a: argparse.Namespace) -> int:
    for row in AuditLog(a.path).tail(a.n, a.session):
        ts = _fmt_time(row.pop("ts", 0))
        print(ts, json.dumps(row, ensure_ascii=False))
    return 0


def _cmd_policy(a: argparse.Namespace) -> int:
    text = resources.files("trifecta_guard").joinpath("default_policy.toml").read_text(encoding="utf-8")
    if a.init:
        if os.path.exists(POLICY_FILENAME) and not a.force:
            print(f"{POLICY_FILENAME} already exists (use --force to overwrite)", file=sys.stderr)
            return 1
        with open(POLICY_FILENAME, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {POLICY_FILENAME}")
        return 0
    if a.effective:
        pol = Policy.load(a.policy, cwd=os.getcwd())
        print(f"# source: {pol.source}")
        print(pol.to_json())
        return 0
    print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trifecta-guard",
                                description="Prompt-injection firewall and taint gate for AI agents.")
    p.add_argument("--version", action="version", version=f"trifecta-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan text for prompt injection (exit 1 if flagged)")
    s.add_argument("path", nargs="?", help="file to scan, or - for stdin (default)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--threshold", type=float)
    s.add_argument("--policy")
    s.set_defaults(fn=_cmd_scan)

    s = sub.add_parser("hook", help="Claude Code hook entry point (reads hook JSON on stdin)")
    s.set_defaults(fn=_cmd_hook)

    s = sub.add_parser("proxy", help="wrap an MCP stdio server: trifecta-guard proxy --name X -- cmd ...")
    s.add_argument("--name", required=True, help="server name; tools become mcp__<name>__<tool>")
    s.add_argument("--session", help="share taint state with other proxies using the same session id")
    s.add_argument("--state-dir", help="where to keep session state (default ~/.trifecta-guard)")
    s.add_argument("--policy")
    s.add_argument("--on-poisoned", choices=["drop", "redact", "warn"], default="drop",
                   help="what to do with tools whose descriptions look poisoned (default: drop)")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=_cmd_proxy)

    s = sub.add_parser("install", help="install hooks: trifecta-guard install claude-code")
    s.add_argument("target", choices=["claude-code"])
    s.add_argument("--scope", choices=["project", "local", "user"], default="project")
    s.add_argument("--project-dir")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--uninstall", action="store_true")
    s.set_defaults(fn=_cmd_install)

    s = sub.add_parser("status", help="show session taint state")
    s.add_argument("session", nargs="?")
    s.add_argument("--state-dir")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=_cmd_status)

    s = sub.add_parser("reset", help="clear a session's taint (after you reviewed what it read)")
    s.add_argument("session")
    s.add_argument("--state-dir")
    s.set_defaults(fn=_cmd_reset)

    s = sub.add_parser("audit", help="show recent decisions from the audit log")
    s.add_argument("-n", type=int, default=20)
    s.add_argument("--session")
    s.add_argument("--path")
    s.set_defaults(fn=_cmd_audit)

    s = sub.add_parser("policy", help="print the default policy, the effective one, or write a starter file")
    s.add_argument("--init", action="store_true", help=f"write {POLICY_FILENAME} in the current directory")
    s.add_argument("--force", action="store_true")
    s.add_argument("--effective", action="store_true", help="print the merged policy in effect here")
    s.add_argument("--policy")
    s.set_defaults(fn=_cmd_policy)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
