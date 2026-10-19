"""The REA bridge speaks MCP over stdio: initialize, tools/call, structured or text results."""

import json
import os
import sys
from pathlib import Path

import pytest

from decompnet import rea

FAKE = r"""
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake-rea", "version": "0"}}
    elif method == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"]["arguments"]
        if name == "open_binary":
            result = {"content": [{"type": "text", "text": json.dumps({"opened": args["path"]})}]}
        elif name == "procedure_pseudo_code":
            result = {"structuredContent": f"int sub_{args['procedure']}(void) {{ return 1; }}"}
        elif name == "analyze_function":
            result = {"structuredContent": {"procedure": {"name": "f", "signature": "int f(void)"}}}
        elif name == "search_strings":
            result = {"structuredContent": [{"address": "0x1000", "value": "hello world"}]}
        elif name == "search_procedures":
            result = {"structuredContent": [{"address": "0x1010", "value": "helper"}]}
        elif name in ("procedure_callers", "procedure_callees", "procedure_references"):
            result = {"structuredContent": [{"address": "0x1020"}]}
        else:
            result = {"content": [{"type": "text", "text": "[]"}]}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


@pytest.fixture
def fake(tmp_path):
    script = tmp_path / "fake_rea.py"
    script.write_text(FAKE)
    return [sys.executable, str(script)]


def test_initialize_and_tool_calls(fake):
    with rea.Client(fake) as client:
        assert client.call("open_binary", {"path": "/tmp/game.exe"}) == {"opened": "/tmp/game.exe"}
        assert client.call("procedure_pseudo_code", {"procedure": "0x1000"}).startswith("int sub_0x1000")


def test_only_allowlisted_tools_run(fake):
    with rea.Client(fake) as client:
        with pytest.raises(rea.ReaError, match="allowlist"):
            client.call("shell", {"command": "rm -rf /"})


def test_command_reads_the_environment(monkeypatch, fake):
    monkeypatch.setenv("DECOMP_REA", " ".join(fake))
    assert rea.command() == fake
    monkeypatch.setenv("DECOMP_REA", "off")
    assert rea.command() is None


def test_draft_uses_the_configured_bridge(monkeypatch, fake, tmp_path):
    monkeypatch.setenv("DECOMP_REA", " ".join(fake))
    monkeypatch.setenv("DECOMP_REA_DRAFTS", "1")
    rea._clients.clear()
    rea._opened.clear()
    rea._cache.clear()
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ" + b"\0" * 100)
    fn = {"vram": 0x1000}
    text = rea.draft(binary, fn, timeout=10)
    assert text and "return 1" in text
    # The second call is served from the cache, without another pseudocode request.
    assert rea.draft(binary, fn, timeout=10) == text
    rea.close_all()


def test_search_and_dossier(fake, monkeypatch, tmp_path):
    from decompnet.rom.symbols import Symbol, SymbolTable
    monkeypatch.setenv("DECOMP_REA", " ".join(fake))
    rea._clients.clear(); rea._opened.clear()
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ" + b"\0" * 100)
    symbols = SymbolTable([Symbol("helper", 0x1010, 8, "func"), Symbol("caller", 0x1020, 8, "func")])
    found = rea.search(binary, "he", symbols, timeout=10)
    assert "hello world" in found and "helper" in found
    fn = {"vram": 0x1000}
    assert "int sub_0x1000" in rea.inspect(binary, fn, symbols, "pseudocode", timeout=10)
    assert "callers: caller" in rea.inspect(binary, fn, symbols, "callers", timeout=10)
    rea.close_all()


def test_missing_bridge_is_not_an_error(monkeypatch):
    monkeypatch.setenv("DECOMP_REA", "off")
    assert rea.command() is None
    assert rea.draft(Path("/nonexistent.exe"), {"vram": 0x1000}, timeout=1) is None
