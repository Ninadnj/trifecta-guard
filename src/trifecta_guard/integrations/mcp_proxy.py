"""Transparent MCP stdio proxy.

    trifecta-guard proxy --name github -- npx -y @modelcontextprotocol/server-github

The proxy launches the real server as a child process and relays newline-delimited JSON-RPC in
both directions. It intervenes in three places:

* ``tools/list`` responses — tool descriptions are scanned for *tool poisoning*; poisoned tools
  are dropped (or their descriptions redacted).
* ``tools/call`` requests — gated by :meth:`Guard.check_call`. A blocked call never reaches the
  server; the client gets a tool error explaining why.
* ``tools/call`` responses — text content is scanned and sanitized by
  :meth:`Guard.inspect_result_obj`, and a warning block is prepended when something was found.

Tool names are qualified as ``mcp__<name>__<tool>`` so the same policy globs work for Claude Code
and for the proxy. Several proxies can share taint state with ``--state-dir`` and ``--session``,
which is what lets the gate see a trifecta that spans servers (read mail on one, post on another).
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
from typing import Any, BinaryIO

from ..guard import Guard

POISON_NOTICE = "[trifecta-guard: description removed, suspected tool poisoning]"


class McpProxy:
    def __init__(self, command: list[str], guard: Guard, name: str, session_id: str,
                 on_poisoned: str = "drop", log=None, hard_exit: bool = False) -> None:
        if on_poisoned not in {"drop", "redact", "warn"}:
            raise ValueError("on_poisoned must be drop | redact | warn")
        self.command = command
        self.guard = guard
        self.name = name
        self.session_id = session_id
        self.on_poisoned = on_poisoned
        self.hard_exit = hard_exit
        self.ask_fallback = guard.policy.gate("ask_fallback")
        self._pending_calls: dict[Any, tuple[str, dict]] = {}
        self._pending_lists: set[Any] = set()
        self._lock = threading.Lock()
        self._out_lock = threading.Lock()
        self._log = log or (lambda msg: print(f"[trifecta-guard:{name}] {msg}", file=sys.stderr, flush=True))

    # --- helpers -----------------------------------------------------------------------------
    def qualified(self, tool: str) -> str:
        return f"mcp__{self.name}__{tool}"

    @staticmethod
    def _key(msg_id: Any) -> str:
        return json.dumps(msg_id)

    def _write(self, stream: BinaryIO, msg: Any) -> None:
        data = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._out_lock:
            stream.write(data)
            stream.flush()

    # --- client -> server ------------------------------------------------------------------
    def handle_client_message(self, msg: Any) -> tuple[Any | None, Any | None]:
        """Returns ``(to_server, to_client)``; either may be ``None``."""
        if isinstance(msg, list):
            fwd, back = [], []
            for m in msg:
                f, b = self.handle_client_message(m)
                if f is not None:
                    fwd.append(f)
                if b is not None:
                    back.append(b)
            return (fwd or None), (back or None)
        if not isinstance(msg, dict) or "method" not in msg or "id" not in msg:
            return msg, None
        method = msg.get("method")
        if method == "tools/call":
            params = msg.get("params") or {}
            tool = self.qualified(str(params.get("name", "")))
            args = params.get("arguments") or {}
            decision = self.guard.check_call(self.session_id, tool, args)
            action = decision.action if decision.action != "ask" else self.ask_fallback
            if action == "deny" or (decision.action == "ask" and action == "ask"):
                self._log(f"blocked {tool}: {decision.message()}")
                return None, {"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "content": [{"type": "text", "text": decision.message() + " (blocked before reaching the server; "
                                 "the user can review with `trifecta-guard status` and `trifecta-guard reset`)"}],
                    "isError": True}}
            with self._lock:
                self._pending_calls[self._key(msg["id"])] = (tool, args)
        elif method == "tools/list":
            with self._lock:
                self._pending_lists.add(self._key(msg["id"]))
        return msg, None

    # --- server -> client ------------------------------------------------------------------
    def handle_server_message(self, msg: Any) -> Any:
        if isinstance(msg, list):
            return [self.handle_server_message(m) for m in msg]
        if not isinstance(msg, dict) or "method" in msg or "id" not in msg:
            return msg
        key = self._key(msg["id"])
        with self._lock:
            call = self._pending_calls.pop(key, None)
            is_list = key in self._pending_lists
            self._pending_lists.discard(key)
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        if call is not None:
            msg["result"] = self._filter_call_result(call[0], call[1], result)
        elif is_list:
            msg["result"] = self._filter_tools(result)
        return msg

    def _filter_call_result(self, tool: str, args: dict, result: dict) -> dict:
        content = result.get("content") or []
        slots: list[tuple[dict, str]] = []
        texts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                slots.append((block, "text"))
                texts.append(block["text"])
            elif block.get("type") == "resource" and isinstance(block.get("resource"), dict) \
                    and isinstance(block["resource"].get("text"), str):
                slots.append((block["resource"], "text"))
                texts.append(block["resource"]["text"])
        payload = {"texts": texts, "structured": result.get("structuredContent")}
        decision = self.guard.inspect_result_obj(self.session_id, tool, args, payload)
        if decision.modified:
            new = decision.text
            for (holder, field), value in zip(slots, new["texts"]):
                holder[field] = value
            if result.get("structuredContent") is not None:
                result["structuredContent"] = new["structured"]
        if decision.notice:
            result["content"] = [{"type": "text", "text": decision.notice}] + list(content)
            self._log(decision.notice)
        return result

    def _filter_tools(self, result: dict) -> dict:
        tools = result.get("tools")
        if not isinstance(tools, list):
            return result
        kept = []
        for tool in tools:
            if not isinstance(tool, dict):
                kept.append(tool)
                continue
            texts = [str(tool.get("description") or "")] + _schema_descriptions(tool.get("inputSchema"))
            verdict = self.guard.scan_tool_description(str(tool.get("name")), "\n".join(texts))
            if not verdict.flagged:
                kept.append(tool)
                continue
            qname = self.qualified(str(tool.get("name")))
            self.guard.audit.write(session=self.session_id, event="tool_poisoning", tool=qname,
                                   action=self.on_poisoned, score=round(verdict.score, 3), rules=verdict.rules[:8])
            self._log(f"tool {qname} looks poisoned ({verdict.summary()}): {self.on_poisoned}")
            if self.on_poisoned == "drop":
                continue
            if self.on_poisoned == "redact":
                tool = dict(tool)
                tool["description"] = POISON_NOTICE
                tool["inputSchema"] = _strip_schema_descriptions(tool.get("inputSchema"))
            else:  # warn: keep it, but the session has now seen hostile text
                with self.guard.store.session(self.session_id) as st:
                    st.tainted = st.compromised = True
                    st.add_event(kind="untrusted_read", tool=qname, flagged=True, rules=verdict.rules[:8])
            kept.append(tool)
        result["tools"] = kept
        return result

    # --- plumbing ----------------------------------------------------------------------------
    def run(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        child = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        assert child.stdin is not None and child.stdout is not None

        def pump_server() -> None:
            for line in iter(child.stdout.readline, b""):
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    with self._out_lock:
                        stdout.write(line)
                        stdout.flush()
                    continue
                try:
                    msg = self.handle_server_message(msg)
                except Exception as exc:  # fail safe: never forward unchecked tool output
                    msg = _error_reply(msg, f"trifecta-guard failed to inspect this result: {exc}")
                self._write(stdout, msg)

        def watch_server() -> None:
            pump_server()
            # The server is gone: tell the client (EOF) instead of leaving it waiting forever.
            code = child.wait()
            if code:
                self._log(f"server exited with code {code}")
            with self._out_lock:
                try:
                    stdout.flush()
                    # sys.stdout is opened with closefd=False, so close the descriptor itself.
                    os.close(stdout.fileno())
                except (OSError, ValueError, io.UnsupportedOperation):
                    try:
                        stdout.close()
                    except OSError:
                        pass
            if self.hard_exit:
                # The main thread is blocked reading the client's stdin; nothing left to relay.
                os._exit(code or 0)

        t = threading.Thread(target=watch_server, daemon=True)
        t.start()
        try:
            for line in iter(stdin.readline, b""):
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    child.stdin.write(line)
                    child.stdin.flush()
                    continue
                try:
                    fwd, back = self.handle_client_message(msg)
                except Exception as exc:
                    fwd, back = None, _error_reply(msg, f"trifecta-guard failed to check this call: {exc}")
                if back is not None:
                    try:
                        self._write(stdout, back)
                    except (OSError, ValueError):
                        break
                if fwd is not None:
                    try:
                        self._write(child.stdin, fwd)
                    except BrokenPipeError:
                        break
        finally:
            try:
                child.stdin.close()
            except OSError:
                pass
            t.join(timeout=5)
            try:
                return child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.terminate()
                return child.wait()


def _error_reply(msg: Any, text: str) -> Any:
    if isinstance(msg, dict) and "id" in msg:
        return {"jsonrpc": "2.0", "id": msg["id"],
                "result": {"content": [{"type": "text", "text": text}], "isError": True}}
    return None


def _schema_descriptions(schema: Any) -> list[str]:
    out: list[str] = []

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("description", "title") and isinstance(v, str):
                    out.append(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(schema)
    return out


def _strip_schema_descriptions(schema: Any) -> Any:
    if isinstance(schema, dict):
        return {k: (POISON_NOTICE if k == "description" and isinstance(v, str) else _strip_schema_descriptions(v))
                for k, v in schema.items()}
    if isinstance(schema, list):
        return [_strip_schema_descriptions(v) for v in schema]
    return schema
