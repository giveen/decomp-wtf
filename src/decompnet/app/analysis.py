"""Analysis projects: REA targets that are not matching-decompilation games.

A matching project asks "what C compiles to these bytes?". An analysis project asks a wider question, and its work
items are procedures (or tasks the user adds): each agent claims one, reads it through REA, and records what it
learned. There is no compiler and no score; a work item is done when an agent writes its findings.

The project reuses the same tables and dashboard as a game: functions are claims, notes are notes, and
status "matched" means "analyzed" for this kind of project.
"""

from __future__ import annotations

import re
from typing import Any


def number(value: Any) -> int | None:
    """An address from REA: 0x-prefixed text, decimal text or an int."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text or text.upper().startswith("EXTERNAL"):
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError:
            return None


def segment_at(address: int, segments: list[dict]) -> str:
    for seg in segments or ():
        start, end = number(seg.get("start")), number(seg.get("end"))
        if start is not None and end is not None and start <= address < end:
            return str(seg.get("name") or "")
    return ""


def procedures(value: Any, segments: list[dict] | None = None) -> list[dict]:
    """REA's list_procedures as work items: [{name, address, size, unit}], internal procedures only."""
    rows = value if isinstance(value, list) else (
        (value or {}).get("procedures") or (value or {}).get("result") or [])
    found: dict[int, dict] = {}
    for row in rows:
        if isinstance(row, dict):
            address = number(row.get("address"))
            name = row.get("value") or row.get("name") or row.get("label")
            proc = row.get("procedure") if isinstance(row.get("procedure"), dict) else {}
            if proc.get("external") or row.get("external"):
                continue
        else:
            address, name, proc = number(row), row, {}
        if address is None:
            continue
        name = str(name or f"sub_{address:X}")
        found.setdefault(address, {"name": name, "address": address, "unit": segment_at(address, segments or [])})
    items = sorted(found.values(), key=lambda x: x["address"])
    for i, item in enumerate(items):
        nxt = items[i + 1]["address"] if i + 1 < len(items) else item["address"]
        size = nxt - item["address"]
        item["size"] = size if 0 < size < (1 << 20) else 0
    return items


def opened_target(value: Any, path: str) -> dict:
    """The target half of REA's open_binary answer (or a best effort for other inspector tools)."""
    value = value or {}
    if isinstance(value, dict) and isinstance(value.get("result"), dict):
        value = value["result"]
    if not isinstance(value, dict):
        value = {}
    return {
        "path": str(value.get("path") or path),
        "format": str(value.get("format") or ""),
        "architecture": str(value.get("architecture") or value.get("arch") or ""),
        "kind": str(value.get("kind") or ""),
        "sha256": str(value.get("sha256") or ""),
        "size": value.get("size") or value.get("byte_size") or None,
    }


def overview_counts(value: Any) -> dict:
    value = value if isinstance(value, dict) else {}
    return {
        "procedures": value.get("procedure_count"),
        "strings": value.get("string_count"),
        "segments": value.get("segment_count"),
    }


def clean_segments(value: Any) -> list[dict]:
    rows = value if isinstance(value, list) else (value or {}).get("segments") or []
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append({k: row.get(k) for k in ("name", "start", "end", "executable", "writable", "initialized")
                    if k in row})
    return out[:200]


def pretty(value: Any, limit: int = 12000) -> str:
    """A REA answer for an agent: strings as they are, everything else as JSON, bounded."""
    if isinstance(value, str):
        text = value
    else:
        import json

        text = json.dumps(value, indent=1, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + f"\n… ({len(text) - limit} more characters)"


def dossier(value: Any) -> str:
    """A readable function dossier from analyze_function: signature, pseudocode, assembly, calls, strings."""
    if not isinstance(value, dict):
        return pretty(value)
    proc = value.get("procedure") if isinstance(value.get("procedure"), dict) else {}
    out: list[str] = []
    sig = proc.get("signature") or proc.get("name")
    if sig:
        out.append(f"signature: {sig}")
    if proc.get("body"):
        body = proc["body"]
        if isinstance(body, dict) and body.get("total_bytes") is not None:
            out.append(f"body: {body['total_bytes']} bytes")
    code = value.get("pseudocode") or value.get("decompiled") or proc.get("pseudocode")
    if isinstance(code, str) and code.strip():
        out += ["", "REA pseudocode (a draft, not the original source):", "```c", code.strip(), "```"]
    asm = value.get("assembly") or proc.get("assembly")
    if isinstance(asm, list):
        asm = "\n".join(str(x) for x in asm)
    if isinstance(asm, str) and asm.strip():
        out += ["", "assembly:", "```asm", asm.strip(), "```"]
    for key, label in (("callers", "callers"), ("callees", "callees"), ("referenced_strings", "strings"),
                       ("referenced_names", "names")):
        rows = value.get(key)
        if rows:
            out += ["", f"{label}: " + summarize(rows)]
    for key, label in (("incoming_references", "incoming references"),
                       ("outgoing_references", "outgoing references")):
        rows = value.get(key)
        if rows:
            out += ["", f"{label}: " + summarize(rows)]
    if not out:
        return pretty(value)
    text = "\n".join(out)
    return text if len(text) <= 20000 else text[:20000] + f"\n… ({len(text) - 20000} more characters; use rea_tool for a narrower view)"


def summarize(rows: Any, limit: int = 30) -> str:
    if not isinstance(rows, list):
        return str(rows)[:1000]
    out = []
    for row in rows[:limit]:
        if isinstance(row, dict):
            addr = row.get("address") or row.get("value") or row.get("name")
            name = row.get("name") or row.get("value")
            target = row.get("target_procedure") or row.get("source_procedure")
            if isinstance(target, dict):
                name = target.get("name") or name
                addr = target.get("address") or addr
            out.append(f"{name or '?'}" + (f" @ {addr}" if addr and str(addr) != str(name) else ""))
        else:
            out.append(str(row))
    more = f" … {len(rows) - limit} more" if len(rows) > limit else ""
    return ", ".join(out) + more


def safe_name(name: str, address: int | None = None) -> str:
    name = re.sub(r"\s+", " ", str(name or "")).strip()
    if not name:
        name = f"sub_{address:X}" if address is not None else "task"
    return name[:80]
