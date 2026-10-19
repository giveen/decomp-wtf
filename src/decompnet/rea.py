"""REA's binary-analysis tools, available to decomp.wtf agents on Windows targets.

REA (https://rea.tools) is a separate MCP server that inspects native binaries with Ghidra, IDA,
Hopper or Rizin: function inventories, pseudocode, cross references, strings, call graphs. This
module speaks MCP to ``rea mcp`` over stdio and exposes a small, path-scoped allowlist. Nothing
here is required for matching: without REA, PE games still import and are judged byte for byte.

Setup (optional): install REA (``npm install -g rea-agents``) and configure its provider, then
either leave ``rea`` on PATH or set ``DECOMP_REA`` to the command (for example
``DECOMP_REA="/opt/rea/scripts/rea.mjs mcp"``). ``DECOMP_REA=off`` disables the bridge.
"""

from __future__ import annotations

import atexit
import json
import os
import queue
import shlex
import shutil
import subprocess
import threading
import time
from pathlib import Path

# Only read-only analysis. Nothing that opens files by arbitrary path after the initial target,
# executes code, writes annotations, or touches the network.
ALLOWED = {
    "open_binary", "binary_overview", "list_procedures", "analyze_function", "procedure_pseudo_code",
    "procedure_assembly", "procedure_info", "procedure_callers", "procedure_callees", "procedure_references",
    "xrefs", "search_procedures", "search_strings", "read_bytes", "list_segments", "list_names", "close_binary",
}


class ReaError(RuntimeError):
    pass


def command() -> list[str] | None:
    """How to start REA's MCP server, or None when it isn't configured on this machine."""
    env = os.environ.get("DECOMP_REA", "").strip()
    if env.lower() in ("off", "0", "false", "no"):
        return None
    if env:
        return shlex.split(env)
    found = shutil.which("rea") or shutil.which("rea-agents")
    if found:
        return [found, "mcp"]
    if os.environ.get("DECOMP_REA_ALLOW_NPX") == "1" and shutil.which("npx"):
        return ["npx", "-y", "rea-agents@latest", "mcp"]
    return None


class Client:
    """A minimal MCP client: initialize, then tools/call by name."""

    def __init__(self, argv: list[str] | None = None, timeout: float = 600):
        argv = argv or command()
        if not argv:
            raise ReaError("REA isn't set up (install rea-agents, put `rea` on PATH or set DECOMP_REA)")
        self.argv, self.timeout = argv, timeout
        self._id = 0
        self._lock = threading.Lock()
        self._lines: queue.Queue[str | None] = queue.Queue()
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, encoding="utf-8", errors="replace", bufsize=1,
                                     env={**os.environ, "NO_COLOR": "1"})
        threading.Thread(target=self._read, daemon=True).start()
        self._initialize()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self._lines.put(line)
        self._lines.put(None)

    def _send(self, message: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def _request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        with self._lock:
            self._id += 1
            ident = self._id
            self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}})
            deadline = time.time() + (timeout or self.timeout)
            while True:
                left = deadline - time.time()
                if left <= 0:
                    raise ReaError(f"REA did not answer {method} in {timeout or self.timeout:.0f}s")
                try:
                    line = self._lines.get(timeout=left)
                except queue.Empty:
                    raise ReaError(f"REA did not answer {method} in {timeout or self.timeout:.0f}s") from None
                if line is None:
                    raise ReaError("REA exited")
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if msg.get("id") == ident and "method" not in msg:
                    if "error" in msg:
                        raise ReaError(str(msg["error"].get("message") or msg["error"]))
                    return msg.get("result") or {}
                if "method" in msg and "id" in msg:  # a server request (ping, roots): answer minimally
                    self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})

    def _initialize(self) -> None:
        self._request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "decomp.wtf", "version": "1"}}, timeout=30)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call(self, tool: str, arguments: dict | None = None, timeout: float | None = None):
        if tool not in ALLOWED:
            raise ReaError(f"REA tool {tool!r} is not on decomp.wtf's allowlist")
        result = self._request("tools/call", {"name": tool, "arguments": arguments or {}}, timeout=timeout)
        if result.get("isError"):
            text = " ".join(c.get("text", "") for c in result.get("content") or [] if isinstance(c, dict))
            raise ReaError(text.strip() or f"REA's {tool} failed")
        if "structuredContent" in result:
            return result["structuredContent"]
        text = "".join(c.get("text", "") for c in result.get("content") or [] if isinstance(c, dict))
        try:
            return json.loads(text)
        except ValueError:
            return text

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                self.proc.kill()
            except OSError:
                pass

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ------------------------------------------------------------------ what the decomp tools use

_clients: dict[str, Client] = {}
_opened: dict[str, str] = {}
_cache: dict[tuple[str, int], str] = {}
_lock = threading.Lock()


def _client(binary: Path) -> Client:
    key = str(binary.resolve())
    client = _clients.get(key)
    if client is None or client.proc.poll() is not None:
        client = Client()
        _clients[key] = client
    if _opened.get(key) != key:
        client.call("open_binary", {"path": key}, timeout=900)
        _opened[key] = key
    return client


def _procedure(fn) -> str:
    return f"0x{int(fn['vram']):X}"


def draft(binary: Path, fn, timeout: float = 60) -> str | None:
    """REA/Ghidra pseudocode as a starting draft, if REA answers in time. Never blocks the claim loop
    for long: a cold Ghidra import takes minutes, and agents can call inspect_binary themselves."""
    if os.environ.get("DECOMP_REA_DRAFTS", "").lower() not in ("1", "on", "yes", "true"):
        return None  # a cold Ghidra import takes minutes; agents ask for a dossier with inspect_binary instead
    key = (str(Path(binary).resolve()), int(fn["vram"]))
    if key in _cache:
        return _cache[key]
    if command() is None:
        return None
    try:
        with _lock:
            text = _client(Path(binary)).call("procedure_pseudo_code", {"procedure": _procedure(fn)},
                                              timeout=timeout)
    except (ReaError, OSError):
        return None
    if not isinstance(text, str) or not text.strip():
        return None
    result = ("/* draft from REA's decompiler (Ghidra) via MCP: a starting point, not a match */\n"
              + text.strip() + "\n")
    _cache[key] = result
    return result


def inspect(binary: Path, fn, symbols, what: str = "", timeout: float = 900) -> str:
    """A function dossier from REA for the inspect_binary tool: pseudocode, signature, callers, references."""
    what = (what or "all").lower()
    parts: list[str] = []
    with _lock:
        client = _client(Path(binary))
        proc = _procedure(fn)
        if what in ("all", "info"):
            dossier = client.call("analyze_function", {"procedure": proc}, timeout=timeout)
            if isinstance(dossier, dict):
                info = dossier.get("procedure") or dossier.get("function") or {}
                if isinstance(info, dict):
                    sig = info.get("signature") or info.get("name")
                    if sig:
                        parts.append(f"signature: {sig}")
        if what in ("all", "pseudocode", "code"):
            code = client.call("procedure_pseudo_code", {"procedure": proc}, timeout=timeout)
            if isinstance(code, str) and code.strip():
                parts += ["", "REA pseudocode (Ghidra; a draft, not the original source):", "```c", code.strip(), "```"]
        if what in ("all", "assembly"):
            asm = client.call("procedure_assembly", {"procedure": proc}, timeout=timeout)
            if isinstance(asm, str) and asm.strip():
                parts += ["", "REA assembly:", "```asm", asm.strip(), "```"]
        if what in ("all", "callers"):
            callers = client.call("procedure_callers", {"procedure": proc}, timeout=timeout)
            if callers:
                parts += ["", "callers: " + _addr_list(callers, symbols)]
        if what in ("all", "callees"):
            callees = client.call("procedure_callees", {"procedure": proc}, timeout=timeout)
            if callees:
                parts += ["", "callees: " + _addr_list(callees, symbols)]
        if what in ("all", "references"):
            refs = client.call("procedure_references", {"procedure": proc, "direction": "outgoing"}, timeout=timeout)
            if refs:
                parts += ["", "references: " + _addr_list(refs, symbols)]
    return "\n".join(parts) or f"REA returned nothing for {what or 'this function'}."


def search(binary: Path, query: str, symbols, timeout: float = 900) -> str:
    """Names and strings in the binary, through REA: the fastest way to find what a game calls."""
    with _lock:
        client = _client(Path(binary))
        rows = []
        try:
            found = client.call("search_strings", {"pattern": query}, timeout=timeout)
            for row in (found if isinstance(found, list) else [])[:40]:
                value = row.get("value") or row.get("text") if isinstance(row, dict) else row
                addr = row.get("address") if isinstance(row, dict) else None
                rows.append(f"- string {symbols.label(int(addr, 0)) if addr is not None else ''}: {str(value)[:160]}")
        except ReaError:
            pass
        try:
            found = client.call("search_procedures", {"pattern": query}, timeout=timeout)
            for row in (found if isinstance(found, list) else [])[:40]:
                addr, value = (row.get("address"), row.get("value") or row.get("name")) if isinstance(row, dict) else (None, row)
                rows.append(f"- procedure {symbols.label(int(addr, 0)) if addr is not None else ''}: {value}")
        except ReaError:
            pass
    return "\n".join(rows) or f"REA found no string or procedure matching {query!r}."


def _addr_list(value, symbols) -> str:
    rows = value if isinstance(value, list) else value.get("addresses") or value.get("references") or []
    out = []
    for row in rows[:40]:
        addr = row.get("address") if isinstance(row, dict) else row
        try:
            at = int(addr, 0) if isinstance(addr, str) else int(addr)
        except (TypeError, ValueError):
            continue
        out.append(symbols.label(at))
    return ", ".join(out) or str(value)[:500]


atexit.register(lambda: close_all())


def close_all() -> None:
    with _lock:
        for client in _clients.values():
            client.close()
        _clients.clear()
        _opened.clear()
