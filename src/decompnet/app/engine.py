"""The local engine: ROM projects on top of the coordination core.

Network (claims, attempts, best attempts, notes, a regression-tested shared header) already does the
bookkeeping several agents need to work on one codebase. A ROM project adds:

- targets taken straight from the ROM (splat), matched by linking the candidate at the function's
  address (rom.match), so a match is byte-identical code;
- a symbol table, so agents can name things (rename_symbol) without breaking matches;
- tools for what ROMs need: split a function the disassembler merged, read data, see who calls what.

Everything stays on this computer.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import shutil
import struct
import threading
import time
from pathlib import Path

from .. import rea, scoring, seeds, similarity, toolchains
from ..elfobj import FunctionObj
from ..network import Agent, Network, NetworkError, _ago, _hash_token
from ..rom import bincompare, buildinfo, debuginfo, detect, library, match, pe, split
from .. import tracefile
from ..rom.symbols import AUTO_NAME, IDENT, Symbol, SymbolTable
from . import analysis

DEFAULT_TOOLCHAIN = {"KMC": "gcc-2.7.2-kmc", "IDO": "ido-7.1", "PSYQ": "gcc-2.7.2-psx", "EEGCC": "ee-gcc-2.96",
                     "AGBCC": "agbcc"}
# How ready each platform is for a full decomp you can port and mod; the GUI and the README show it.
# recommended: the most tested path, from import to a project that builds the game (GameCube and Wii: the same kind
# of project as decomp.dev's, linked file by file as it's finished; N64: tested on real games, rebuilt byte for byte).
# beta: works and is tested on homemade games, less so on real ones yet.
PLATFORM_STATUS = {"gc": "recommended", "wii": "recommended", "n64": "recommended",
                   "psx": "beta", "ps2": "beta", "gba": "beta", "nds": "beta", "windows": "beta", "linux": "beta"}
# PC programs: split from the executable itself (pe.py, elfexe.py) and judged by the x86 matcher.
X86_PLATFORMS = ("windows", "linux")
# C++ drivers: the source is compiled as C++ (see toolchains.toml), and the UI and agent prompt say C++.
CXX_TOOLCHAINS = ("gxx-", "clangxx-", "mingwxx-", "clang-clxx-")
# What imported APIs and strings usually mean. Hints, not proof: the report says which functions use them.
SUBSYSTEM_HINTS = (
    ("render", ("d3d", "dxgi", "opengl", "vulkan", "glbind", "glclear", "glgen", "gltex", "glvertex",
                "shader", "texture", "sprite", "render", "gdi", "bitblt", "drawtext", "font")),
    ("audio", ("dsound", "xaudio", "openal", "fmod", "audio", "sound", "waveout", "mixer", "music")),
    ("input", ("dinput", "xinput", "getkeystate", "getasynckeystate", "joystick", "keyboard", "mouse")),
    ("network", ("ws2", "winsock", "socket", "connect", "recv", "send", "http", "curl", "inet")),
    ("file/registry", ("createfile", "readfile", "writefile", "fopen", "fclose", "findfirst", "findnext",
                       "deletefile", "movefile", "copyfile", "regopen", "regquery", "regset", "registry")),
    ("ui", ("user32", "messagebox", "createwindow", "dialogbox", "getdlgitem", "setwindowtext", "menu")),
    ("memory", ("malloc", "free", "realloc", "calloc", "heapalloc", "virtualalloc", "virtualfree",
                "memcpy", "memset", "memmove")),
    ("threading", ("createthread", "thread", "mutex", "criticalsection", "waitforsingle", "sleep")),
    ("crypto", ("crypt", "aes", "sha1", "sha256", "md5", "rsa", "ssl", "tls")),
)


def source_language(toolchain: str) -> str:
    return "C++" if toolchain.startswith(CXX_TOOLCHAINS) else "C"


def source_ext(toolchain: str) -> str:
    return ".cpp" if source_language(toolchain) == "C++" else ".c"


def cxx_toolchain(toolchain: str) -> str:
    """The C++ driver for a C toolchain on the same target, when there is one."""
    for c, cpp in (("mingw-", "mingwxx-"), ("clang-cl-", "clang-clxx-"),
                   ("gcc-linux-", "gxx-linux-"), ("clang-linux-", "clangxx-linux-")):
        if toolchain.startswith(c):
            return cpp + toolchain[len(c):]
    return toolchain


def arch_toolchain(toolchain: str, arch: str) -> str:
    """The same PC compiler for the target's architecture (a 32-bit import must not compile x86-64)."""
    suffix = "x86_64" if arch == "x86_64" else "x86"
    for old in ("x86_64", "x86"):
        if toolchain.endswith("-" + old):
            candidate = toolchain[: -len(old)] + suffix
            try:
                toolchains.get(candidate)
            except toolchains.ToolchainError:
                return toolchain
            return candidate
    return toolchain


LINUX_COMPILERS = {
    "gcc-linux-x86_64": ("GCC (x86-64)", "Linux programs (x86-64), with the GCC on this machine"),
    "gxx-linux-x86_64": ("G++ (x86-64)", "Linux C++ programs (x86-64), with the G++ on this machine"),
    "clang-linux-x86_64": ("Clang (x86-64)", "Linux programs (x86-64), with the Clang on this machine"),
    "clangxx-linux-x86_64": ("Clang++ (x86-64)", "Linux C++ programs (x86-64), with the Clang++ on this machine"),
    "gcc-linux-x86": ("GCC (x86)", "Linux programs (32-bit x86), with the GCC on this machine"),
    "gxx-linux-x86": ("G++ (x86)", "Linux C++ programs (32-bit x86), with the G++ on this machine"),
    "clang-linux-x86": ("Clang (x86)", "Linux programs (32-bit x86), with the Clang on this machine"),
    "clangxx-linux-x86": ("Clang++ (x86)", "Linux C++ programs (32-bit x86), with the Clang++ on this machine"),
}
COMPILERS = {
    **{k: use for k, (_short, use) in LINUX_COMPILERS.items()},
    "mingw-x86_64": "Windows games (x86-64), with the GCC on this machine",
    "mingw-x86": "Windows games (32-bit x86), with the GCC on this machine",
    "mingwxx-x86_64": "Windows C++ games (x86-64), with the G++ on this machine",
    "mingwxx-x86": "Windows C++ games (32-bit x86), with the G++ on this machine",
    "clang-cl-x86_64": "Windows games (x86-64), with LLVM's MSVC-compatible clang-cl",
    "clang-cl-x86": "Windows games (32-bit x86), with LLVM's MSVC-compatible clang-cl",
    "clang-clxx-x86_64": "Windows C++ games (x86-64), with LLVM's MSVC-compatible clang-cl",
    "clang-clxx-x86": "Windows C++ games (32-bit x86), with LLVM's MSVC-compatible clang-cl",
    "gcc-2.7.2-kmc": "many third-party N64 games",
    "ido-7.1": "most later first-party N64 games",
    "ido-5.3": "early N64 games (1996-97)",
    "gcc-2.7.2-psx": "PlayStation games (PSY-Q era GCC)",
    "gcc-2.8.1-psx": "later PlayStation games",
    "ee-gcc-2.96": "PlayStation 2 games (Sony's EE GCC)",
    "agbcc": "Game Boy Advance games (pret's agbcc, GCC 2.95)",
}
SHORT_NAMES = {"gcc-2.7.2-kmc": "KMC GCC 2.7.2", "ido-7.1": "IDO 7.1", "ido-5.3": "IDO 5.3",
               "gcc-2.7.2-psx": "GCC 2.7.2 (PS1)", "gcc-2.8.1-psx": "GCC 2.8.1 (PS1)", "ee-gcc-2.96": "EE-GCC 2.96",
               "agbcc": "agbcc", "mingw-x86_64": "MinGW-w64 GCC (x86-64)", "mingw-x86": "MinGW-w64 GCC (x86)",
               "mingwxx-x86_64": "MinGW-w64 G++ (x86-64)", "mingwxx-x86": "MinGW-w64 G++ (x86)",
               "clang-cl-x86_64": "clang-cl (x86-64)", "clang-cl-x86": "clang-cl (x86)",
               "clang-clxx-x86_64": "clang-cl (x86-64, C++)", "clang-clxx-x86": "clang-cl (x86, C++)",
               "llvm-tools": "LLVM tools", "upx": "UPX", "rizin": "Rizin", "detect-it-easy": "Detect It Easy",
               **{k: short for k, (short, _use) in LINUX_COMPILERS.items()}}
# CodeWarrior versions in the `mwcc` pack (GameCube, Wii) and the `mwccarm` pack (DS), for games started from scratch.
MW_VERSIONS = {
    "gc": ["GC/1.0", "GC/1.1", "GC/1.1p1", "GC/1.2.5", "GC/1.2.5n", "GC/1.3", "GC/1.3.2", "GC/1.3.2r", "GC/2.0",
           "GC/2.0p1", "GC/2.5", "GC/2.6", "GC/2.7", "GC/3.0a3", "GC/3.0a3.2", "GC/3.0a3.3", "GC/3.0a3.4", "GC/3.0a5",
           "GC/3.0a5.2"],
    "wii": ["Wii/0x4201_127", "Wii/1.0RC1", "Wii/1.0a", "Wii/1.0", "Wii/1.1", "Wii/1.3", "Wii/1.5", "Wii/1.6", "Wii/1.7"],
    "ds": ["DS/1.2/base", "DS/1.2/sp2", "DS/1.2/sp2p3", "DS/1.2/sp3", "DS/1.2/sp4", "DS/2.0/base", "DS/2.0/sp1",
           "DS/2.0/sp1p2", "DS/2.0/sp1p5", "DS/2.0/sp1p6", "DS/2.0/sp1p7", "DS/2.0/sp2", "DS/2.0/sp2p2", "DS/2.0/sp2p3",
           "DS/2.0/sp2p4", "DS/dsi/1.1", "DS/dsi/1.1p1", "DS/dsi/1.2", "DS/dsi/1.2p1", "DS/dsi/1.2p2", "DS/dsi/1.3",
           "DS/dsi/1.3p1", "DS/dsi/1.6sp1", "DS/dsi/1.6sp2"],
}

# Tools shown in Setup besides the compilers.
TOOLS = {
    "m2c": "machine-made first drafts (MIPS, PowerPC, ARM)",
    "objdiff-cli": "judges forks of public decomps, function by function",
    "ghidra": "drafts for PC, Switch and other platforms m2c can't read (540 MB, needs Java 21+)",
    "rea": "the RE console and the agents' inspect_binary (needs Node.js; native code needs Ghidra, Hopper or IDA)",
    "mwcc": "CodeWarrior, the compilers of GameCube and Wii games (proprietary)",
    "mwccarm": "CodeWarrior for DS, the compilers of DS games (proprietary)",
    "dsd": "ds-decomp: analyses DS ROMs and rebuilds them",
    "llvm-tools": "PDB debug symbols for Windows programs (system LLVM; optional)",
    "upx": "unpack UPX-packed PC programs before splitting (optional)",
    "rizin": "lightweight analysis provider for REA (optional)",
    "detect-it-easy": "compiler and packer fingerprints (optional)",
}
WINDOWS_NOTE = """
/* Windows globals: define them here WITHOUT `extern` (for example `int g_counter;`). With `extern`, MinGW
 * assumes the name may come from a DLL and loads it through an extra pointer, which never matches the
 * game's direct RIP-relative access. Imported functions are the exception: declare those
 * `__declspec(dllimport)`, which is exactly the indirect call through the import table the game makes. */
"""
LINUX_NOTE = """
/* Linux: calls into shared libraries (memcpy, printf, operator new) go through the program's PLT stubs, which
 * are named after the function: declare them yourself (system headers can't be included). Globals can be
 * `extern` or defined here. With a C++ compiler the names to match are the mangled ones (_ZN7Archive4OpenEv):
 * write the C++ that mangles to them, or wrap a sub_<address> you write in `extern "C" { ... }`. */
"""

# Functions this small are handed out in batches (claim_function count): agents match most on the first try.
BATCH_INSNS = 48
PLATFORM_COMPILERS = {"n64": ["gcc-2.7.2-kmc", "ido-7.1", "ido-5.3"], "psx": ["gcc-2.7.2-psx", "gcc-2.8.1-psx"],
                      "ps2": ["ee-gcc-2.96"], "gba": ["agbcc"],
                      "windows": ["mingw-x86_64", "mingw-x86", "mingwxx-x86_64", "mingwxx-x86",
                                  "clang-cl-x86_64", "clang-cl-x86", "clang-clxx-x86_64", "clang-clxx-x86"],
                      "linux": list(LINUX_COMPILERS)}


def _linux_flags(flags: list[str], pie: bool) -> list[str]:
    """A Linux toolchain's flags for this program: position-independent programs are compiled -fPIE."""
    return [f for f in flags if f not in ("-fno-pic", "-fno-pie")] + ["-fPIE"] if pie else list(flags)


_AUTO_TOKEN = re.compile(r"\b(?:func|D|B|jtbl|RO|STR|FLT|DBL)_[0-9A-F]{8}\b")
_ADDRESS = re.compile(r"^(?:0x)?([0-9A-Fa-f]{8})$")

GP_NOTE = """
/* This game keeps small globals (8 bytes or less) in $gp-relative small data. Declare those here WITHOUT
 * `extern` (for example `s32 D_8001B278;`): then the compiler reads them through $gp, like the game does.
 * With `extern`, it builds the full address instead and the function can't match. */
"""

BASE_HEADER = """/* context.h for {title}: shared by every function. Agents grow it with edit_context:
 * add a prototype or struct the moment you work one out, so the next function benefits. */

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
typedef float f32;
typedef double f64;
typedef volatile u8 vu8;
typedef volatile u16 vu16;
typedef volatile u32 vu32;
typedef volatile s32 vs32;
typedef int s32_bool;

#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define ARRAY_COUNT(arr) (s32)(sizeof(arr) / sizeof(arr[0]))
"""


def _slugify(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug[:40] or "rom"


def _preview(data: bytes | None, kind: str) -> str:
    if not data:
        return ""
    text = data.split(b"\0", 1)[0]
    if len(text) >= 3 and all(32 <= c < 127 or c in (9, 10) for c in text):
        return json.dumps(text.decode("ascii"))
    return data[:16].hex(" ")


class RomNetwork(Network):
    def __init__(self, db_path: str | Path, workspace: Path, claim_ttl: int = 30 * 60,
                 agent_secret: str | None = None):
        super().__init__(db_path, claim_ttl=claim_ttl)
        self.workspace = Path(workspace)
        # Stable for the install (CLI: .decomp/agent.secret): a helper's MCP bridge must keep working when the
        # app restarts. Tests and tools without a secret get a per-process one.
        self._agent_secret = agent_secret or secrets.token_urlsafe(32)
        self._syms: dict[int, SymbolTable] = {}
        self._sym_override: dict[int, SymbolTable] = {}
        self._roms: dict[int, tuple[bytes, list[split.Segment]]] = {}
        self._xrefs: dict[int, dict] = {}
        self._seed_lock = threading.Lock()
        self.links: dict = {}  # slug -> collab.Link, for projects joined from a friend's room
        self.rooms: dict = {}  # slug -> collab.Room, for projects this computer shares
        self._remote_ids: dict[str, int] = {}
        self._ops: dict[int, dict] = {}  # project id -> look-alike index
        self._diffs: dict[tuple, dict] = {}  # (function, source, context, compiler) -> diff for the GUI
        self.autopilots: dict[str, dict] = {}  # slug -> progress of trying every function's machine draft
        from .forkengine import ForkEngine  # forks build on this class's claims, attempts and live view
        from .permute import Permuter
        from .twins import Twins
        self.forks = ForkEngine(self)
        self.twins = Twins(self)
        self.permuter = Permuter(self)

    # ------------------------------------------------------------------ basics

    def _require_budget(self, agent: Agent) -> None:
        """Your machine, your agent: no compile budget."""

    @staticmethod
    def cfg(proj) -> dict:
        return json.loads(proj["config"])

    def is_rom(self, proj) -> bool:
        return self.cfg(proj).get("kind") == "rom"

    def is_analysis(self, proj) -> bool:
        return self.cfg(proj).get("kind") == "analysis"

    # ------------------------------------------------------------------ analysis projects (REA)

    def analysis_cfg(self, slug: str) -> tuple:
        proj = self._project(slug)
        if not self.is_analysis(proj):
            raise NetworkError(f"{slug} isn't an analysis project")
        cfg = self.cfg(proj)
        return proj, cfg

    def import_analysis(self, path: str | Path, *, tool: str = "open_binary", arguments: dict | None = None,
                        provider: str = "", confirmed: bool = False, copy_target: bool = False,
                        log=print) -> str:
        """Open anything with REA as a project: procedures become work items, and agents read them in parallel."""
        if not confirmed:
            raise NetworkError("confirm that you are authorized to analyze this target")
        target_path = Path(path).expanduser().resolve()
        if not target_path.is_file():
            raise NetworkError(f"no file at {target_path}")
        if analysis.is_archive(target_path) and target_path.stat().st_size > analysis.MAX_ARCHIVE_INPUT:
            raise NetworkError(f"that archive is larger than {analysis.MAX_ARCHIVE_INPUT // (1024 ** 3)} GiB; "
                               "extract the part you need and analyze that instead")
        target = {"path": str(target_path), "tool": tool or "open_binary", "arguments": arguments or {}}
        for row in self.store.all("SELECT slug, config FROM projects"):
            cfg = json.loads(row["config"])
            old = cfg.get("target") or {}
            if cfg.get("kind") == "analysis" and old.get("path") == target["path"] and old.get("tool") == target["tool"]:
                log(f"already imported as {row['slug']}")
                return row["slug"]

        log(f"opening {target_path.name} with REA ({target['tool']})…")
        base = _slugify(target_path.stem or "analysis")
        slug, n = base, 2
        while self.store.one("SELECT 1 FROM projects WHERE slug=?", slug) or (self.workspace / slug).exists():
            slug, n = f"{base}-{n}", n + 1
        workdir = self.workspace / slug
        workdir.mkdir(parents=True)
        if copy_target:
            kept = workdir / target_path.name
            shutil.copy2(target_path, kept)
            target_path = kept
            target["path"] = str(target_path)
        try:
            attempts = [target["tool"]]
            if target["tool"] == "open_binary":
                suffix = target_path.suffix.lower()
                extra = ({"inspect_firmware_regions" if suffix in (".bin", ".img", ".fw", ".rom")
                          else "analyze_javascript_application" if suffix in (".js", ".asar")
                          else "inspect_android_package" if suffix == ".apk"
                          else "inspect_managed_artifact" if suffix in (".dll", ".exe")
                          else None})
                if extra:
                    attempts.append(extra)
            error = None
            for tool in attempts:
                try:
                    target["tool"] = tool
                    client, opened = rea.open_analysis(target, provider)
                    break
                except rea.ReaError as e:
                    error = e
            else:
                raise error or rea.ReaError("REA couldn't open this target")
            info = analysis.opened_target(opened, str(target_path))
            inventory = None
            if analysis.is_archive(target_path):
                try:
                    inventory = analysis.artifact_inventory(client.call(
                        "inspect_artifact", {}, timeout=analysis.INSPECT_TIMEOUT, any_tool=True))
                except rea.ReaError as e:
                    log(f"archive inventory failed: {e}")
                    inventory = None
                if inventory is not None:
                    analysis.validate_inventory(inventory)
            try:
                overview = client.call("binary_overview", {}, timeout=900)
            except rea.ReaError:
                overview = {}
            try:
                segments = analysis.clean_segments(client.call("list_segments", {}, timeout=900))
            except rea.ReaError:
                segments = []
            try:
                items = analysis.procedures(client.call("list_procedures", {}, timeout=900), segments)
            except rea.ReaError:
                items = []
            entries = analysis.artifact_entries(inventory) if inventory is not None else []
            for item in entries:
                if item.get("entry_type") == "unknown":
                    try:
                        head = analysis.read_archive_entry(target_path, item["path"], 0, 16)
                        item.update(analysis.classify_entry(item["path"], head))
                    except (OSError, ValueError):
                        pass
            if entries:
                items = entries
        except BaseException:
            shutil.rmtree(workdir, ignore_errors=True)
            raise
        counts = analysis.overview_counts(overview)
        if counts.get("segments") is None:
            counts["segments"] = len(segments)
        if inventory is not None:
            occurrences = inventory.get("occurrences") or []
            counts["entries"] = len(occurrences)
            counts["files"] = len(entries)
            counts["directories"] = sum(1 for o in occurrences if isinstance(o, dict) and o.get("entry_kind") == "directory")
        if counts.get("procedures") is None or entries:
            counts["procedures"] = len(items)
        if not items:  # anything without a procedure inventory still gets one survey item
            items = [{"name": "survey", "address": 0, "size": 0, "unit": ""}]
            log("no procedures listed: the project starts with one survey task; add more tasks in the project")
        if entries:
            log(f"{info.get('format') or 'archive'}: {len(entries)} files from {counts.get('entries', len(entries))} entries")
        else:
            log(f"{info.get('format') or 'target'} {info.get('architecture') or ''}: {len(items)} work items")

        cfg = {
            "kind": "analysis", "platform": "rea", "target": info | {"tool": target["tool"],
                                                                      "arguments": target["arguments"]},
            "provider": provider or "", "counts": counts, "segments": segments,
            "artifact": ({"format": info.get("format") or "", "entries": counts.get("entries", 0),
                          "files": counts.get("files", 0), "directories": counts.get("directories", 0),
                          "inspection_id": inventory.get("inspection_id") if inventory else ""}
                         if inventory is not None else None),
            "legal": {"basis": "authorized", "license": "user's own use",
                      "statement": "opened by the user, who confirmed they are authorized to analyze it",
                      "confirmed_at": time.time()},
            "context": {"file": None},
        }
        work_items = f"{len(items)} work item" + ("" if len(items) == 1 else "s")
        description = (f"{info.get('format') or 'target'} · {counts.get('entries')} entries · {work_items}"
                       if inventory is not None and entries else
                       f"{info.get('format') or 'target'} · {info.get('architecture') or 'unknown'} · {work_items}")
        now = time.time()
        names: set[str] = set()
        with self.store.tx() as db:
            pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) "
                             "VALUES(?,?,?,?,?,?,?)",
                             (slug, target_path.name, description, info.get("architecture") or "unknown", 0,
                              str(workdir), json.dumps(cfg))).lastrowid
            for item in items:
                name = analysis.safe_name(item["name"], item.get("address"))
                if name in names:  # an archive can repeat a basename in two directories
                    base, n = name, 2
                    while name in names:
                        name, n = f"{base}~{n}", n + 1
                names.add(name)
                if item.get("kind") == "artifact-entry":
                    meta = {"kind": "artifact-entry", "address": 0, **{k: item.get(k) for k in (
                        "path", "entry_kind", "artifact_kind", "artifact_format", "sha256", "compressed_size",
                        "executable", "encrypted", "entry_type", "entry_format", "tool", "analyzable")}}
                else:
                    meta = {"kind": "survey" if name == "survey" and not item.get("address") else "procedure",
                            "address": item.get("address") or 0}
                db.execute(
                    "INSERT INTO functions(project_id,name,size,n_insns,unit,vram,meta,status) VALUES(?,?,?,?,?,?,?,?)",
                    (pid, name, item.get("size") or 0, 0, item.get("unit") or "", item.get("address") or 0,
                     json.dumps(meta), "open"))
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (pid, 1, f"// REA analysis target: {target_path}\n", None,
                                                  "analysis target", now, ""))
            self._event(db, pid, None, "import", f"{len(items)} work items from {target_path.name}")
        return slug

    def add_analysis_task(self, agent: Agent | None, slug: str, name: str, brief: str = "") -> str:
        proj, cfg = self.analysis_cfg(slug)
        name = analysis.safe_name(name)
        if self.store.one("SELECT 1 FROM functions WHERE project_id=? AND name=?", proj["id"], name):
            raise NetworkError(f"{name!r} is already a work item")
        now = time.time()
        with self.store.tx() as db:
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,unit,vram,meta,status) VALUES(?,?,?,?,?,?,?,?)",
                       (proj["id"], name, 0, 0, "", 0, json.dumps({"kind": "task", "brief": brief.strip()}), "open"))
            self._event(db, proj["id"], agent.id if agent else None, "task", name)
        return name

    def analysis_tool(self, slug: str, tool: str, arguments: dict | None = None) -> str:
        """Run one read-only REA tool on an analysis project's target."""
        _, cfg = self.analysis_cfg(slug)
        if tool not in rea.ANALYSIS_ALLOWED:
            raise NetworkError(f"REA tool {tool!r} isn't available to agents; allowed: "
                               f"{', '.join(sorted(rea.ANALYSIS_ALLOWED))}")
        try:
            client = rea.analysis_client(cfg["target"], cfg.get("provider") or "")
            value = client.call(tool, arguments or {}, timeout=1800, any_tool=True)
        except rea.ReaError as e:
            raise NetworkError(str(e)) from e
        return analysis.pretty(value)

    def analysis_search(self, slug: str, query: str) -> str:
        _, cfg = self.analysis_cfg(slug)
        try:
            client = rea.analysis_client(cfg["target"], cfg.get("provider") or "")
        except rea.ReaError as e:
            raise NetworkError(str(e)) from e
        rows: list[str] = []
        try:
            found = client.call("search_strings", {"pattern": query}, timeout=900)
            if isinstance(found, list):
                rows += [f"- string {analysis.summarize([r])}" for r in found[:40]]
        except rea.ReaError:
            pass
        try:
            found = client.call("search_procedures", {"pattern": query}, timeout=900)
            if isinstance(found, list):
                rows += [f"- procedure {analysis.summarize([r])}" for r in found[:40]]
        except rea.ReaError:
            pass
        return "\n".join(rows) or f"REA found no string or procedure matching {query!r}."

    def analysis_read_entry(self, slug: str, entry: str, offset: int = 0, length: int = 256) -> str:
        """Read one file inside an archive project, without extracting it to disk."""
        _, cfg = self.analysis_cfg(slug)
        if not cfg.get("artifact"):
            raise NetworkError("this analysis project isn't an archive")
        data = analysis.read_archive_entry((cfg.get("target") or {}).get("path") or "", entry,
                                           max(0, int(offset)), max(1, min(int(length), 8192)))
        if data is None:
            raise NetworkError(f"no entry {entry!r} in this archive (or it couldn't be read)")
        return f"{entry} + 0x{max(0, int(offset)):X} ({len(data)} bytes)\n" + analysis.preview_bytes(data, len(data))

    def analysis_summary(self, slug: str) -> dict:
        """Write SUMMARY.md: the target, every analyzed work item's finding, and what is still open."""
        proj, cfg = self.analysis_cfg(slug)
        target = cfg.get("target") or {}
        artifact = cfg.get("artifact") or {}
        rows = self.store.all(
            "SELECT f.name, f.size, f.status, f.meta, f.matched_source, f.matched_at, a.name AS agent "
            "FROM functions f LEFT JOIN agents a ON a.id=f.matched_agent_id "
            "WHERE f.project_id=? ORDER BY f.status='matched' DESC, f.unit, f.name", proj["id"])
        analyzed = [r for r in rows if r["status"] == "matched"]
        pending = [r for r in rows if r["status"] != "matched"]
        notes = self.store.all(
            "SELECT n.text, n.created_at, a.name AS agent FROM notes n LEFT JOIN agents a ON a.id=n.agent_id "
            "WHERE n.project_id=? AND n.function_id IS NULL ORDER BY n.id DESC", proj["id"])
        now = time.time()
        findings = f"{len(analyzed)} finding" + ("" if len(analyzed) == 1 else "s")
        summary = (f"{len(analyzed)}/{len(rows)} work items analyzed · {findings}"
                   + (f" · {artifact.get('entries')} archive entries" if artifact.get("entries") else ""))
        lines = [f"# Analysis summary: {proj['name']}", "",
                 f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} for project `{proj['slug']}`.", "",
                 "## Target",
                 f"- file: `{target.get('path') or ''}`",
                 f"- format: {target.get('format') or 'file'} · kind: {target.get('kind') or 'target'}",
                 f"- provider: {cfg.get('provider') or 'auto'}",
                 f"- progress: {summary}"]
        if artifact.get("entries"):
            dirs, files = artifact.get("directories") or 0, artifact.get("files") or 0
            lines.append(f"- archive: {artifact.get('entries')} entries · {files} file{'' if files == 1 else 's'} · "
                         f"{dirs} director{'y' if dirs == 1 else 'ies'}")
        lines += ["", "## Findings"]
        if not analyzed:
            lines += ["Nothing has been analyzed yet.", ""]
        for row in analyzed:
            meta = json.loads(row["meta"] or "{}")
            path = meta.get("path") or row["name"]
            lines += [f"### `{path}`"]
            facts = [f"{row['size']} bytes"]
            if meta.get("artifact_format"):
                facts.append(str(meta["artifact_format"]))
            if meta.get("sha256"):
                facts.append(f"sha256 {meta['sha256']}")
            lines.append("- " + " · ".join(facts))
            when = _ago(row["matched_at"]) if row["matched_at"] else "earlier"
            lines.append(f"- analyzed by {row['agent'] or 'an agent'} {when}")
            lines += ["", (row["matched_source"] or "").strip() or "(no finding text)", ""]
        if pending:
            lines += ["## Still open"]
            for row in pending:
                meta = json.loads(row["meta"] or "{}")
                label = meta.get("path") or row["name"]
                lines.append(f"- `{label}` — {row['status']}")
            lines.append("")
        if notes:
            lines += ["## Project notes"]
            for note in notes:
                lines.append(f"- {note['text'].strip()}" + (f" — {note['agent']}" if note["agent"] else ""))
            lines.append("")
        children = cfg.get("children") or []
        if children:
            lines += ["## Nested targets"]
            for child in children:
                if not isinstance(child, dict) or not child.get("slug"):
                    continue
                try:
                    cproj = self._project(child["slug"])
                except NetworkError:
                    lines.append(f"- `{child.get('entry')}` → `{child['slug']}` (missing)")
                    continue
                cagg = self.store.one(
                    "SELECT COUNT(*) AS total, SUM(status='matched') AS matched FROM functions WHERE project_id=?",
                    cproj["id"])
                cpath = Path(cproj["root"]) / "SUMMARY.md"
                lines += [f"### `{child.get('entry')}` → `{child['slug']}`",
                          f"- target: {cproj['name']} · {cagg['matched'] or 0}/{cagg['total'] or 0} analyzed",
                          f"- summary: {cpath}"]
                for crow in self.store.all(
                        "SELECT name, meta, matched_source FROM functions WHERE project_id=? AND status='matched' "
                        "ORDER BY name", cproj["id"]):
                    cmeta = json.loads(crow["meta"] or "{}")
                    label = cmeta.get("path") or crow["name"]
                    finding = " ".join((crow["matched_source"] or "").split())
                    lines.append(f"- `{label}`: {finding[:300]}" + ("…" if len(finding) > 300 else ""))
                lines.append("")
        while lines and lines[-1] == "":
            lines.pop()
        lines += ["", "## What this means",
                  "The findings above are agent-written observations, not verified original source. Read the target "
                  "again with REA when a claim matters, and add a task for anything still unanswered."]
        markdown = "\n".join(lines).rstrip() + "\n"
        path = Path(proj["root"]) / "SUMMARY.md"
        path.write_text(markdown, encoding="utf-8")
        self._update_cfg(slug, lambda c: c.__setitem__("summary", {"file": "SUMMARY.md", "generated_at": now}))
        return {"slug": slug, "kind": "analysis", "title": proj["name"], "generated_at": now,
                "summary": summary, "complete": bool(rows) and not pending, "children": len(children),
                "markdown": markdown, "path": str(path)}

    def _artifact_entry_row(self, proj, entry: str):
        for row in self.store.all("SELECT * FROM functions WHERE project_id=?", proj["id"]):
            meta = json.loads(row["meta"] or "{}")
            if meta.get("kind") == "artifact-entry" and meta.get("path") == entry:
                return row, meta
        return None, None

    def analysis_contents(self, slug: str) -> dict:
        """The archive's files as a tree for the project page, including which entries already have child targets."""
        proj, cfg = self.analysis_cfg(slug)
        artifact = cfg.get("artifact") or {}
        children = {str(c.get("entry")): c for c in cfg.get("children") or [] if isinstance(c, dict)}
        root = {"name": proj["name"], "path": "", "kind": "directory", "children": {}}
        for row in self.store.all("SELECT name, size, meta FROM functions WHERE project_id=?", proj["id"]):
            meta = json.loads(row["meta"] or "{}")
            if meta.get("kind") != "artifact-entry":
                continue
            path = str(meta.get("path") or row["name"])
            parts = [p for p in path.split("/") if p not in ("", ".")]
            if not parts:
                continue
            node = root
            for i, part in enumerate(parts[:-1]):
                node = node["children"].setdefault(part, {"name": part, "path": "/".join(parts[:i + 1]),
                                                          "kind": "directory", "children": {}})
            child = children.get(path)
            node["children"][parts[-1]] = {
                "name": parts[-1], "path": path, "kind": "file", "size": row["size"],
                "entry_type": meta.get("entry_type") or "unknown", "entry_format": meta.get("entry_format") or "",
                "tool": meta.get("tool") or "", "analyzable": bool(meta.get("analyzable")),
                "sha256": meta.get("sha256") or "", "child": child.get("slug") if child else None,
            }

        def clean(node):
            if node["kind"] == "file":
                return node
            kids = sorted(node["children"].values(), key=lambda n: (n["kind"] != "directory", n["name"].lower()))
            return {"name": node["name"], "path": node["path"], "kind": "directory",
                    "children": [clean(k) for k in kids]}

        return {"slug": slug, "title": proj["name"], "format": artifact.get("format") or "archive",
                "entries": artifact.get("entries") or 0, "files": artifact.get("files") or 0,
                "nodes": [clean(n) for n in sorted(root["children"].values(),
                                                  key=lambda n: (n["kind"] != "directory", n["name"].lower()))]}

    def analyze_archive_entry(self, slug: str, entry: str, log=print) -> dict:
        """Extract one archive entry and open it as a linked analysis project. Never extracts the whole archive."""
        proj, cfg = self.analysis_cfg(slug)
        artifact = cfg.get("artifact") or {}
        if not artifact:
            raise NetworkError("this analysis project isn't an archive")
        depth = int((cfg.get("source") or {}).get("depth") or 0)
        if depth >= analysis.MAX_NESTING:
            raise NetworkError(f"nested targets stop at {analysis.MAX_NESTING} levels; open this entry separately")
        row, meta = self._artifact_entry_row(proj, entry)
        if row is None:
            raise NetworkError(f"no file named {entry!r} in this archive project")
        tool = str(meta.get("tool") or "")
        if not meta.get("analyzable"):
            data = analysis.read_archive_entry((cfg.get("target") or {}).get("path") or "", entry, 0, 16)
            info = analysis.classify_entry(entry, data)
            tool = str(info.get("tool") or "")
            if tool:
                meta = {**meta, **info}
        if not tool:
            raise NetworkError(f"{entry} isn't a target type this app can open yet")

        children = cfg.get("children") or []
        for child in children:
            if isinstance(child, dict) and child.get("entry") == entry and child.get("slug"):
                log(f"{entry} is already open as {child['slug']}")
                return {"slug": child["slug"], "entry": entry, "existing": True}

        sha = str(meta.get("sha256") or "")
        target_path = Path((cfg.get("target") or {}).get("path") or "")
        if not target_path.is_file():
            raise NetworkError(f"the archive is gone: {target_path}")
        folder = Path(proj["root"]) / "extracted" / (sha[:16] or hashlib.sha256(entry.encode()).hexdigest()[:16])
        name = Path(entry).name or "entry.bin"
        dest = folder / name
        if not dest.exists():
            size = int(meta.get("size") or 0)
            extract_root = Path(proj["root"]) / "extracted"
            extracted = sum(p.stat().st_size for p in extract_root.rglob("*") if p.is_file()) if extract_root.exists() else 0
            if extracted + size > analysis.MAX_EXTRACTED_BYTES:
                raise NetworkError(f"this project already has {extracted // (1024 * 1024)} MiB of extracted files; "
                                   f"the limit is {analysis.MAX_EXTRACTED_BYTES // (1024 * 1024)} MiB")
            if shutil.disk_usage(proj["root"]).free < size + (64 * 1024 * 1024):
                raise NetworkError("not enough free disk space for this entry")
            total, digest = analysis.extract_archive_entry(target_path, entry, dest)
            if sha and digest != sha:
                dest.unlink(missing_ok=True)
                raise NetworkError(f"{entry} changed while it was being extracted (hash mismatch)")
            log(f"extracted {entry} ({total} bytes)")

        tool = str(meta.get("tool") or tool)
        child = self.import_analysis(dest, tool=tool, provider=cfg.get("provider") or "", confirmed=True,
                                     copy_target=True, log=log)
        source = {"kind": "artifact-entry", "parent": proj["slug"], "parent_title": proj["name"],
                  "entry": entry, "entry_sha256": sha, "archive": target_path.name,
                  "archive_sha256": (cfg.get("target") or {}).get("sha256") or "", "tool": tool,
                  "depth": depth + 1}
        self._update_cfg(child, lambda c: c.__setitem__("source", source))
        child_row = self.project_row(child)

        def remember(c):
            kids = c.setdefault("children", [])
            if not any(isinstance(k, dict) and k.get("slug") == child for k in kids):
                kids.append({"slug": child, "title": child_row["name"], "entry": entry, "entry_sha256": sha,
                             "tool": tool})
        self._update_cfg(slug, remember)
        with self.store.tx() as db:
            self._event(db, proj["id"], None, "entry", f"{entry} → {child}")
        try:
            self.analysis_summary(slug)
        except Exception:
            pass
        log(f"{entry} opened as {child}")
        return {"slug": child, "entry": entry, "existing": False, "tool": tool}

    def analysis_read_data(self, slug: str, what: str, length: int = 64) -> str:
        _, cfg = self.analysis_cfg(slug)
        address = what
        try:
            fn = self._function(what, slug)
            address = f"0x{int(fn['vram']):X}"
        except NetworkError:
            pass
        try:
            value = rea.analysis_client(cfg["target"], cfg.get("provider") or "").call(
                "read_bytes", {"address": address, "length": max(1, min(int(length), 512))}, timeout=900)
        except rea.ReaError as e:
            raise NetworkError(str(e)) from e
        return analysis.pretty(value)

    def _analysis_brief(self, fn, agent: Agent | None, header: str) -> str:
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        cfg = self.cfg(proj)
        target = cfg.get("target") or {}
        meta = json.loads(fn["meta"] or "{}")
        claim = self.store.one("SELECT * FROM claims WHERE function_id=?", fn["id"])
        lines = [f"## {header}: {proj['slug']}/{fn['name']}",
                 f"target: {target.get('path')}",
                 f"{target.get('format') or 'file'} · {target.get('architecture') or 'unknown'} · "
                 f"{target.get('kind') or 'analysis target'}"]
        if meta.get("address"):
            lines.append(f"address: 0x{int(meta['address']):X}")
        if claim:
            who = "you" if agent and claim["agent_id"] == agent.id else self._agent_name(claim["agent_id"])
            lines.append(f"claimed by {who}, lease expires in {int(claim['expires_at'] - time.time()) // 60} min")
        if fn["status"] == "matched":
            lines += [f"ANALYZED by {self._agent_name(fn['matched_agent_id'])} {_ago(fn['matched_at'])}:",
                      fn["matched_source"].strip()]
        if meta.get("kind") == "task" and meta.get("brief"):
            lines += ["", "The user's task:", meta["brief"]]
        if meta.get("kind") == "artifact-entry":
            path = str(meta.get("path") or fn["name"])
            lines += ["", f"archive entry: {path}", f"size: {fn['size']} bytes"]
            if meta.get("sha256"):
                lines.append(f"sha256: {meta['sha256']}")
            if meta.get("executable"):
                lines.append("executable: yes")
            if meta.get("encrypted"):
                lines.append("encrypted: yes")
            data = analysis.read_archive_entry(target.get("path") or "", path, 0, 4096)
            lines += ["", "entry preview (bounded):", "```", analysis.preview_bytes(data), "```"]
            lines += ["", "Read more with read_artifact_entry(entry, offset, length); the archive inventory is "
                          "available through rea_tool(\"inspect_artifact\", {})."]
        else:
            try:
                client = rea.analysis_client(target, cfg.get("provider") or "")
                if meta.get("kind") == "procedure" and meta.get("address"):
                    dossier = client.call("analyze_function", {"procedure": f"0x{int(meta['address']):X}"}, timeout=1800)
                    lines += ["", analysis.dossier(dossier)]
                else:
                    ov = client.call("binary_overview", {}, timeout=900)
                    segs = analysis.clean_segments(client.call("list_segments", {}, timeout=900))
                    lines += ["", "REA overview:", analysis.pretty(ov)]
                    if segs:
                        lines += ["", "segments:", analysis.pretty(segs)]
            except rea.ReaError as e:
                lines += ["", f"REA couldn't read this item: {e}", "Try another view with rea_tool."]
        notes = self.store.all(
            "SELECT n.text, n.created_at, a.name FROM notes n LEFT JOIN agents a ON a.id=n.agent_id "
            "WHERE n.function_id=? ORDER BY n.id DESC LIMIT 8", fn["id"])
        if notes:
            lines += ["", "### Notes from previous agents"] + [
                f"- ({n['name']}, {_ago(n['created_at'])}) {n['text']}" for n in notes]
        pnotes = self.store.all(
            "SELECT n.text, a.name FROM notes n LEFT JOIN agents a ON a.id=n.agent_id "
            "WHERE n.project_id=? AND n.function_id IS NULL ORDER BY n.id DESC LIMIT 5", proj["id"])
        if pnotes:
            lines += ["", "### Project-wide notes"] + [f"- ({n['name']}) {n['text']}" for n in pnotes]
        if header == "CLAIMED":
            if meta.get("kind") == "artifact-entry":
                lines += ["", "Next: read_artifact_entry(entry, offset, length) for more of this file, write what "
                              "matters with add_note, then complete_function(function, summary). Release it with "
                              "notes if it needs someone else."]
            else:
                lines += ["", "Next: investigate with rea_tool (search_strings, search_procedures, xrefs, list_segments…), "
                              "write what matters with add_note, then complete_function(function, summary). "
                              "Release it with notes if it needs someone else."]
        return "\n".join(lines)

    def complete_analysis(self, agent: Agent, project: str | None, function: str, summary: str) -> str:
        fn = self._function(function, project)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        if not self.is_analysis(proj):
            raise NetworkError("complete_function is for analysis projects; compile_and_diff matches a game")
        cfg = self.cfg(proj)
        summary = summary.strip()
        if not summary:
            raise NetworkError("write the finding first: what this item does, what it calls, what matters")
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} is already analyzed")
        now = time.time()
        with self.store.tx() as db:
            claim = db.execute("SELECT agent_id FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
            if claim is None or claim["agent_id"] != agent.id:
                raise NetworkError(f"you don't hold a claim on {fn['name']}")
            db.execute("UPDATE functions SET status='matched', matched_source=?, matched_agent_id=?, matched_at=?, "
                       "best_score=0, best_source=? WHERE id=?", (summary, agent.id, now, summary, fn["id"]))
            db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
            db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                       (proj["id"], fn["id"], agent.id, summary, now))
            self._event(db, proj["id"], agent.id, "analyze", fn["name"])
        done = self.store.one("SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND status!='matched'",
                              proj["id"])["n"] == 0
        if done:
            try:
                self.analysis_summary(proj["slug"])
            except Exception:
                pass
        parent = (cfg.get("source") or {}).get("parent")
        if parent:
            try:
                self.analysis_summary(parent)
            except Exception:
                pass
        return (f"✅ {fn['name']} is analyzed and saved. Your finding is on it and in the project's notes. "
                "Call claim_function for the next item, or add_note about the target as a whole."
                + (" The project summary is in SUMMARY.md." if done else ""))


    def project_row(self, slug: str):
        return self._project(slug)

    def fork_slug(self, project: str | None) -> str | None:
        """The slug when `project` is a fork of a public decomp, else None."""
        try:
            proj = self._project(project)
        except NetworkError:
            return None
        return proj["slug"] if self.cfg(proj).get("kind") == "fork" else None

    def _rom_only(self, project: str | None, what: str) -> None:
        if self.fork_slug(project):
            raise NetworkError(f"{what} is for ROM projects. In a fork, the project's own headers and source files are "
                               "the shared context: use read_file, search_code and edit_file")

    def symbols(self, project_id: int) -> SymbolTable:
        if project_id in self._sym_override:
            return self._sym_override[project_id]
        if project_id not in self._syms:
            rows = self.store.all("SELECT name, address, size, kind FROM symbols WHERE project_id=?", project_id)
            self._syms[project_id] = SymbolTable([Symbol(r["name"], r["address"], r["size"], r["kind"]) for r in rows])
        return self._syms[project_id]

    def _rom(self, proj) -> tuple[bytes, list[split.Segment]]:
        if proj["id"] not in self._roms:
            cfg = self.cfg(proj)
            rom = (Path(proj["root"]) / cfg["rom"]["file"]).read_bytes()
            segs = [split.Segment(**s) for s in cfg["segments"]]
            self._roms[proj["id"]] = (rom, segs)
        return self._roms[proj["id"]]

    def reader(self, proj):
        rom, segs = self._rom(proj)

        def read(addr: int, n: int) -> bytes | None:
            for seg in segs:
                if seg.contains(addr, n):
                    at = seg.rom_start + addr - seg.vram
                    return rom[at:at + n]
            return None
        return read

    def _function(self, name: str, project: str | None):
        """Functions can also be named by address (0x80001234), handy for agents reading assembly, and the way
        agents write names they read elsewhere (see _loose_functions)."""
        m = _ADDRESS.match(name.strip()) if name else None
        if m:
            proj = self._project(project)
            row = self.store.one("SELECT * FROM functions WHERE project_id=? AND vram=?", proj["id"], int(m.group(1), 16))
            if row is not None:
                return row
        try:
            return super()._function(name, project)
        except NetworkError as e:
            rows = self._loose_functions(name, project) if name else []
            if len(rows) == 1:
                return rows[0]
            if rows:
                raise NetworkError(self._ambiguous(name, rows)) from None
            near = self._near_names(name, project) if name else []
            if near:
                raise NetworkError(f"{e}. Did you mean: {', '.join(near)}?") from None
            raise

    def _near_names(self, name: str, project: str | None, n: int = 5) -> list[str]:
        """Function names close to one that doesn't exist (a typo, another spelling of the symbol)."""
        import difflib

        try:
            proj = self._project(project)
        except NetworkError:
            return []
        sym = name.strip().strip("`'\"").split("@", 1)[0].split("(", 1)[0].strip()
        if len(sym) < 3:
            return []
        rows = self.store.all("SELECT name FROM functions WHERE project_id=? AND (name LIKE ? OR name LIKE ?) LIMIT 4000",
                              proj["id"], f"%{sym[-6:]}%", f"{sym[:4]}%")
        names = [r["name"] for r in rows]
        return difflib.get_close_matches(sym, names, n=n, cutoff=0.6) or [x for x in names if sym in x][:n]

    def _loose_functions(self, name: str, project: str | None) -> list:
        """Functions an agent may mean by a name that isn't stored as such: the plain symbol of a function whose
        name repeats across a fork's files (stored as symbol@unit), symbol@unit for one that doesn't repeat,
        Class::method, a name with its parameter list or in quotes."""
        try:
            proj = self._project(project)
        except NetworkError:
            return []
        text = name.strip().strip("`'\"").strip()
        sym, _, unit = text.partition("@")
        unit, _, nth = unit.partition("#")
        sym = sym.split("(", 1)[0].strip()
        if not sym:
            return []
        rows = self.store.all(
            "SELECT * FROM functions WHERE project_id=? AND (name=? OR substr(name,1,?)=? "
            "OR json_extract(meta,'$.symbol')=? OR substr(json_extract(meta,'$.demangled'),1,?)=?) ORDER BY name",
            proj["id"], sym, len(sym) + 1, sym + "@", sym, len(sym) + 1, sym + "(")
        if unit:
            rows = ([r for r in rows if r["unit"] == unit] or [r for r in rows if r["unit"].endswith(unit)]
                    or [r for r in rows if r["unit"].startswith(unit)] or [r for r in rows if unit in r["unit"]])
        if nth.isdigit() and len(rows) > 1:
            rows = [r for r in rows if (json.loads(r["meta"] or "{}").get("nth", 0) + 1) == int(nth)] or rows
        return [r for r in rows if r["status"] != "nosource"] or rows  # ones in files without source can't be worked on

    @staticmethod
    def _ambiguous(name: str, rows: list) -> str:
        listing = "\n".join(f"- {r['name']} ({r['status']}, {r['n_insns']} instructions)" for r in rows[:12])
        more = f"\n... and {len(rows) - 12} more" if len(rows) > 12 else ""
        return (f"{name!r} is the name of {len(rows)} functions in different files; pass the full name:\n"
                f"{listing}{more}")

    def resolve_function(self, agent: Agent | None, project: str | None, name: str) -> str:
        """The stored name for what an agent calls a function: when a plain name fits several, the one the agent
        holds a claim on."""
        try:
            return self._function(name, project)["name"]
        except NetworkError:
            rows = self._loose_functions(name, project) if name else []
            held = self.store.all("SELECT f.id, f.unit FROM claims c JOIN functions f ON f.id=c.function_id "
                                  "WHERE c.agent_id=?", agent.id) if agent else []
            if held and len(rows) > 1:  # one it holds, else the one in the file (or module) it works in
                ids, units = {h["id"] for h in held}, {h["unit"] for h in held}
                modules = {u.split("/", 1)[0] for u in units}
                for pick in ([r for r in rows if r["id"] in ids], [r for r in rows if r["unit"] in units],
                             [r for r in rows if r["unit"].split("/", 1)[0] in modules]):
                    if len(pick) == 1:
                        return pick[0]["name"]
            raise

    def _rom_target(self, fn) -> match.RomTarget:
        proj = self.store.one("SELECT config FROM projects WHERE id=?", fn["project_id"])
        cfg = json.loads(proj["config"])
        return match.RomTarget(fn["name"], fn["vram"], fn["target"], match.RomTarget.relocs_from_json(json.loads(fn["relocs"])),
                               cfg.get("big_endian", True), cfg.get("gp", 0))

    def _make_target(self, proj, rf: split.RomFunction, syms: SymbolTable) -> match.RomTarget:
        cfg = self.cfg(proj)
        return match.target_from_split(rf, syms.resolve, cfg.get("big_endian", True), cfg.get("gp", 0))

    def _x86_target(self, fn, proj):
        from ..rom import match_x86

        cfg = self.cfg(proj)
        return match_x86.X86Target(fn["name"], cfg.get("arch", "x86_64"), fn["target"],
                                   match_x86.X86Target.relocs_from_json(json.loads(fn["relocs"] or "[]")))

    def _target_obj(self, fn, proj):
        if not self.is_rom(proj):
            return super()._target_obj(fn, proj)
        if self.cfg(proj).get("platform") in X86_PLATFORMS:
            from ..rom import match_x86

            return match_x86.target_obj(self._x86_target(fn, proj), self.symbols(proj["id"]))
        if self.cfg(proj).get("platform") == "gba":
            return FunctionObj(fn["name"], "thumb", False, fn["target"], [])
        return match.canonical_target(self._rom_target(fn), self.symbols(proj["id"]))

    def _evaluate(self, fn, proj, obj: bytes):
        if not self.is_rom(proj):
            return super()._evaluate(fn, proj, obj)
        if self.cfg(proj).get("platform") in X86_PLATFORMS:
            from ..rom import match_x86

            res = match_x86.link(obj, fn["name"], self._x86_target(fn, proj), self.symbols(proj["id"]))
            return res.candidate, res.exact if res.candidate is not None else None, res.problems
        if self.cfg(proj).get("platform") == "gba":
            from ..rom import match_arm

            res = match_arm.link(obj, fn["name"], match_arm.ArmTarget(fn["name"], fn["vram"], fn["target"]),
                                 self.symbols(proj["id"]), self.reader(proj))
            return res.candidate, res.exact if res.candidate is not None else None, res.problems
        res = match.link(obj, fn["name"], self._rom_target(fn), self.symbols(proj["id"]), self.reader(proj))
        return res.candidate, res.exact if res.candidate is not None else None, res.problems

    def _twin_lines(self, proj, fn) -> list[str]:
        """For a brief: the matched function with the same code, and its C with this one's names."""
        try:
            twin_id = self.twins.twin_of(proj, fn["id"])
        except Exception:
            return []
        if twin_id is None:
            return []
        a = self.store.one("SELECT * FROM functions WHERE id=?", twin_id)
        source = self.twins.source_for(proj, a, fn)
        out = ["", f"### Identical code: {a['name']} is the same machine code and already matches"]
        if source and len(source) < 6000:
            out += ["Its C with this function's names (try it first):", "```c", source.strip(), "```"]
        return out

    def rename_tokens(self, proj, text: str) -> str:
        """Show automatic names under their current names (func_80001234 -> deflate)."""
        syms = self.symbols(proj["id"])
        return _AUTO_TOKEN.sub(lambda m: syms.label(int(m.group(0)[-8:], 16)), text)

    def _asm_text(self, fn, proj) -> str:
        if not self.is_rom(proj):
            return super()._asm_text(fn, proj)
        return self.rename_tokens(proj, fn["asm"])

    # ------------------------------------------------------------------ import

    def import_rom(self, data: bytes | Path, *, toolchain: str | None = None, flags: list[str] | None = None,
                   confirmed: bool = False, name: str = "", log=print) -> str:
        """Import a game the user owns (ROM bytes, or a file such as a disc image): split it, store every function
        as a target. Returns the slug."""
        if not confirmed:
            raise NetworkError("confirm that this is your own legally obtained copy of the game")
        source = Path(data).expanduser().resolve() if isinstance(data, (str, Path)) else None
        digest = None
        if source is not None:
            try:
                h = hashlib.sha1()
                with source.open("rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                digest = h.hexdigest()
                log(f"checking {source.name} ({source.stat().st_size // 1024} KiB)")
            except OSError:
                digest = None
        elif isinstance(data, (bytes, bytearray)):
            digest = hashlib.sha1(data).hexdigest()
        if digest is not None:
            for p in self.store.all("SELECT slug, config FROM projects"):
                if json.loads(p["config"]).get("rom", {}).get("sha1") == digest:
                    log(f"already imported as {p['slug']}")
                    return p["slug"]
        project_file = self._community_layout(data, name)
        if project_file is not None:  # a dtk-template or ds-decomp project, worked on like a fork
            compiler = toolchain if toolchain and toolchain.startswith(("GC/", "Wii/", "DS/")) else None
            return self.forks.create_scratch(project_file, compiler=compiler, log=log)
        log(f"finding functions in {source.name if source is not None else (name or 'the file')}…")
        picked = detect.identify(data, name)
        rom, info = picked.data, picked.info
        for p in self.store.all("SELECT slug, config FROM projects"):
            if json.loads(p["config"]).get("rom", {}).get("sha1") == info["sha1"]:
                log(f"already imported as {p['slug']}")
                return p["slug"]
        base = _slugify(info["title"])
        slug, n = base, 2
        while self.store.one("SELECT 1 FROM projects WHERE slug=?", slug) or (self.workspace / slug).exists():
            slug, n = f"{base}-{n}", n + 1
        workdir = self.workspace / slug
        workdir.mkdir(parents=True)
        (workdir / picked.filename).write_bytes(rom)
        size = f"{info['size'] // (1024 * 1024)} MiB" if info["size"] >= 1 << 20 else f"{info['size'] // 1024} KiB"
        log(f"{detect.PLATFORMS[picked.platform]}: {info['title']} ({info['game_code'] or 'no game code'}, "
            f"{info['region']}), {size}, looks built with {info.get('build_label') or info['compiler_guess']}")
        if picked.platform == "gba":
            return self._import_gba(picked, slug, workdir, toolchain, flags, log)
        if picked.platform in X86_PLATFORMS:
            return self._import_windows(picked, slug, workdir, toolchain, flags, log, source=source)
        if picked.overlays:
            log(f"{len(picked.overlays)} overlay{'s' if len(picked.overlays) != 1 else ''} on the disc: "
                + ", ".join(f"{o[0]} at 0x{o[2]:08X}" for o in picked.overlays[:6]) + (", ..." if len(picked.overlays) > 6 else ""))
        res = split.split_rom(workdir, picked.filename, log=log, overlays=picked.overlays)
        if res.image and res.image != picked.filename:  # splat works on a flat image made from the program
            rom = (workdir / res.image).read_bytes()

        toolchain = toolchain or DEFAULT_TOOLCHAIN.get(res.compiler, DEFAULT_TOOLCHAIN[info["compiler_guess"]])
        tc = toolchains.get(toolchain)
        default_flags = tc.flags
        if picked.platform in ("psx", "ps2"):
            default_flags = [f for f in tc.flags if not f.startswith("-G")] + [f"-G{8 if res.gp else 0}"]
        cfg = {
            "kind": "rom", "platform": picked.platform, "big_endian": picked.big_endian, "gp": res.gp,
            "rom": {**info, "file": res.image or picked.filename, "program": picked.filename},
            "segments": [vars(s) for s in res.segments],
            "compiler": {"toolchain": toolchain, "flags": flags or default_flags, "timeout": 20},
            "legal": {"basis": "personal-copy", "license": "personal use only",
                      "statement": "imported by the owner of this copy of the game, who confirmed it was legally obtained",
                      "confirmed_at": time.time()},
            "context": {"file": None},
        }
        symbols = SymbolTable()
        for name, addr in res.named.items():
            symbols.add(Symbol(name, addr, 0, "func"), reindex=False)
        for fn in res.functions:
            symbols.add(Symbol(fn.name, fn.vram, fn.size, "func"), reindex=False)
        rom_bytes, segs = rom, res.segments

        def read(addr, n):
            for seg in segs:
                if seg.contains(addr, n):
                    at = seg.rom_start + addr - seg.vram
                    return rom_bytes[at:at + n]
            return None

        data_rows = []
        for d in res.data:
            if d.name in symbols.by_name:
                continue
            symbols.add(Symbol(d.name, d.vram, d.size, d.kind), reindex=False)
            data_rows.append((d.name, d.vram, d.size, d.kind, _preview(read(d.vram, min(d.size, 48)), d.kind) if d.kind != "bss" else ""))
        symbols._reindex()

        now = time.time()
        with self.store.tx() as db:
            pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                             (slug, info["title"], f"{info['game_code']} · {info['region']} · {len(res.functions)} functions",
                              "mips", int(picked.big_endian), str(workdir), json.dumps(cfg))).lastrowid
            for fn in res.functions:
                target = match.target_from_split(fn, symbols.resolve, picked.big_endian, res.gp)
                db.execute(
                    "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (pid, fn.name, fn.size, len(fn.lines), target.code, json.dumps(target.to_json()),
                     self._asm_source(fn), None, fn.segment, fn.vram, fn.rom))
            for s in symbols.by_name.values():
                preview = next((r[4] for r in data_rows if r[0] == s.name), None)
                db.execute("INSERT INTO symbols(project_id,name,address,size,kind,preview) VALUES(?,?,?,?,?,?)",
                           (pid, s.name, s.address, s.size, s.kind, preview))
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (pid, 1, BASE_HEADER.format(title=info["title"]) + (GP_NOTE if res.gp else ""),
                                                  None, "basic types", now, ""))
            self._event(db, pid, None, "import", f"{len(res.functions)} functions from {info['title']}")
        log(f"ready: {len(res.functions)} functions to decompile")
        return slug

    def _import_gba(self, picked, slug: str, workdir: Path, toolchain: str | None, flags: list[str] | None, log) -> str:
        """Game Boy Advance: functions found by luvdis (plus a pass for code nothing calls), judged by the ARM matcher."""
        from ..rom import gba

        info = picked.info
        fns = gba.split(workdir / picked.filename, workdir, log=log)
        toolchain = toolchain or "agbcc"
        tc = toolchains.get(toolchain)
        cfg = {
            "kind": "rom", "platform": "gba", "big_endian": False, "gp": 0, "arch": "thumb",
            "rom": {**info, "file": picked.filename, "program": picked.filename},
            "segments": [{"name": "rom", "rom_start": 0, "rom_end": info["size"], "vram": gba.BASE}],
            "compiler": {"toolchain": toolchain, "flags": flags or tc.flags, "timeout": 20},
            "legal": {"basis": "personal-copy", "license": "personal use only",
                      "statement": "imported by the owner of this copy of the game, who confirmed it was legally obtained",
                      "confirmed_at": time.time()},
            "context": {"file": None},
        }
        now = time.time()
        with self.store.tx() as db:
            pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                             (slug, info["title"], f"{info['game_code']} · {info['region']} · {len(fns)} functions",
                              "arm", 0, str(workdir), json.dumps(cfg))).lastrowid
            names: set[str] = set()
            for f in fns:
                name = f.asm_only or f.name  # known hand-written helpers keep their real name and stay assembly
                if name in names:  # a game can link a helper twice (Spyro Orange has two of _call_via_r3)
                    name = f"{name}_{f.vram:08X}"
                names.add(name)
                db.execute(
                    "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset,status) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (pid, name, len(f.code), f.n_insns, f.code, json.dumps([list(r) for r in f.refs or []]),
                     f.asm.replace(f.name, name), None, "rom", f.vram, f.rom, "asm" if f.asm_only else "open"))
                db.execute("INSERT INTO symbols(project_id,name,address,size,kind,preview) VALUES(?,?,?,?,?,?)",
                           (pid, name, f.vram, len(f.code), "func", None))
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (pid, 1, BASE_HEADER.format(title=info["title"]), None, "basic types", now, ""))
            self._event(db, pid, None, "import", f"{len(fns)} functions from {info['title']}")
        log(f"ready: {len(fns)} functions to decompile")
        return slug

    @staticmethod
    def _merge_debug(image, debug) -> None:
        """Put the names a PDB/DWARF/MAP already knows onto the split functions, without inventing new work items."""
        by_addr = {f.vram: f for f in image.functions}
        names = {s.name for s in image.symbols}
        for meta in debug.functions:
            fn = by_addr.get(meta.address)
            if fn is None or not meta.name or not IDENT.match(meta.name):
                continue
            if fn.name == meta.name:
                continue
            if meta.name in names:
                continue  # another function or data already owns that name
            old = fn.name
            fn.name = meta.name
            fn.asm = (fn.asm.replace(f"glabel {old}", f"glabel {meta.name}")
                      .replace(f"endlabel {old}", f"endlabel {meta.name}"))
            for sym in image.symbols:
                if sym.address == meta.address and sym.name == old:
                    sym.name, sym.kind = meta.name, "func"
                    if meta.size:
                        sym.size = meta.size
            names.discard(old)
            names.add(meta.name)
        by_name = {s.name: s for s in image.symbols}
        for sym in debug.symbols:
            if sym.name not in by_name:
                image.symbols.append(sym)
                by_name[sym.name] = sym
            elif sym.kind == "func" and by_name[sym.name].kind != "func":
                by_name[sym.name].kind = "func"

    def _import_windows(self, picked, slug: str, workdir: Path, toolchain: str | None, flags: list[str] | None,
                        log, source: Path | None = None) -> str:
        """Windows and Linux programs: functions from .pdata/.eh_frame/exports/symbols/call targets, matched
        against a compiled object by the x86 matcher. The target is the program's own image, so every function's
        bytes and addresses are final."""
        from ..rom import elfexe

        linux = picked.platform == "linux"
        image = getattr(picked, "image", None) or (elfexe if linux else pe).read(picked.data, picked.filename)
        info = picked.info  # the name the user picked (not the canonical game.exe the copy is stored as)
        debug = None
        try:
            debug = debuginfo.discover(source or (workdir / picked.filename), picked.data, image=image)
        except (debuginfo.DebugInfoError, OSError, ValueError) as e:
            log(f"debug information not imported: {e}")
        if debug is not None:
            self._merge_debug(image, debug)
            log(f"debug information from {debug.source}: {len(debug.symbols)} names, {len(debug.types)} types")
        packed = not linux and (b"UPX!" in picked.data[:0x1000] or any(s.name.upper().startswith("UPX") for s in image.sections))
        if packed:
            log("this looks UPX-packed: unpack it first (UPX is in Compilers & tools), then import the unpacked program")
        suffix = "x86_64" if image.arch == "x86_64" else "x86"
        cxx = buildinfo.looks_cxx(image.symbols)
        requested = toolchain
        if toolchain:
            toolchain = arch_toolchain(toolchain, image.arch)
            if cxx and source_language(toolchain) != "C++":
                toolchain = cxx_toolchain(toolchain)
            if toolchain != requested:
                log(f"using {toolchain} for this {image.arch} target (not {requested})")
        if linux:
            # .comment names the compiler; C++ programs call into libstdc++, whose names are mangled (_Z...).
            family = "clang" if info.get("language_guess") == "Rust" or "clang" in info["compiler_guess"].lower() else "gcc"
            driver = {"gcc": "gxx", "clang": "clangxx"}[family] if cxx else family
            toolchain = toolchain or f"{driver}-linux-{suffix}"
        elif not toolchain:
            # MSVC's ABI is matched by clang-cl; MinGW's by MinGW's C++ driver.
            msvc = info["compiler_guess"] == "MSVC" or any(s.name.startswith("?") for s in image.symbols)
            toolchain = f"{'clang-clxx' if msvc else 'mingwxx'}-{suffix}" if cxx else f"mingw-{suffix}"
        tc = toolchains.get(toolchain)
        base_flags = flags or (_linux_flags(tc.flags, info.get("pie", False)) if linux else tc.flags)
        suggestion = buildinfo.infer_flags(
            picked.data, compiler="MSVC" if toolchain.startswith("clang-cl") else "GNU", cxx=cxx,
            base_flags=base_flags, symbols=image.symbols, section_names=[s.name for s in image.sections])
        info["suggested_flags"] = suggestion["flags"]
        info["flag_evidence"] = suggestion["evidence"]
        info["flag_style"] = suggestion["style"]
        if not flags and suggestion["flags"] != list(tc.flags):
            flags = suggestion["flags"]
            info["flags_inferred"] = True
            log("build flags inferred: " + " ".join(flags))
        log(f"detected {info.get('build_label') or info['compiler_guess']}; matching with {tc.name}")
        if info.get("matchable") is False:
            log(f"{info.get('build_label') or 'this language'} can't be rebuilt from C/C++: inspect and annotate it, "
                f"but functions won't match the original compiler output")
        if toolchains.installed(toolchain) is None:
            log(f"{tc.name} isn't on this computer: functions import and can be inspected, but compiling needs it "
                f"(install it, or set another [compiler] for the project)")
        if linux and not flags:
            flags = base_flags
        cfg = {
            "kind": "rom", "platform": picked.platform, "arch": image.arch, "big_endian": False, "gp": 0,
            "packed": bool(packed),
            "rom": {**info, "file": picked.filename, "program": picked.filename},
            "segments": image.segments,
            "compiler": {"toolchain": toolchain, "flags": flags or tc.flags, "timeout": 20},
            "legal": {"basis": "personal-copy", "license": "personal use only",
                      "statement": "imported by the owner of this copy of the game, who confirmed it was legally obtained",
                      "confirmed_at": time.time()},
            "context": {"file": None},
        }
        if debug is not None and (debug.header or debug.functions):
            cfg["debug"] = {"source": debug.source, "symbols": len(debug.symbols), "types": len(debug.types),
                            "header": debug.header, "imported_at": time.time()}
        names: set[str] = set()
        now = time.time()
        header = BASE_HEADER.format(title=info["title"]) + (LINUX_NOTE if linux else WINDOWS_NOTE)
        if debug is not None and debug.header:
            debug_header = header + "\n/* Debug information imported from " + debug.source.replace("*/", "") + " */\n" + debug.header
            try:
                from ..compiler import compile_source
                from ..project import compiler_config
                if not compile_source(compiler_config(workdir, cfg), debug_header, "").ok:
                    log("debug types don't compile with this project's compiler: keeping them out of the shared header")
                else:
                    header = debug_header
            except Exception as e:
                log(f"debug types not added to the shared header: {e}")
        with self.store.tx() as db:
            pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                             (slug, info["title"], f"{image.arch} · {len(image.functions)} functions · "
                                                   f"{info['compiler_guess']}", image.arch, 0, str(workdir),
                              json.dumps(cfg))).lastrowid
            libs = 0
            for f in image.functions:
                name = f.name
                if name in names:
                    name = f"{name}_{f.vram:08X}"
                names.add(name)
                lib = library.kind(f.name)
                libs += bool(lib)
                db.execute(
                    "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset,status,meta) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (pid, name, len(f.code), f.n_insns, f.code, json.dumps([list(r) for r in f.refs]),
                     f.asm.replace(f.name, name), None, f.section, f.vram, f.rom,
                     "library" if lib else "open", json.dumps({"library": lib}) if lib else None))
            for sym in image.symbols:
                db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind,preview) "
                           "VALUES(?,?,?,?,?,?)", (pid, sym.name, sym.address, sym.size, sym.kind, sym.preview or None))
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (pid, 1, header, None, "basic types", now, ""))
            self._event(db, pid, None, "import", f"{len(image.functions)} functions from {info['title']}")
        log(f"ready: {len(image.functions)} functions to decompile" + (f" ({libs} library/CRT functions skipped)" if libs else ""))
        return slug

    # ------------------------------------------------------------------ debug symbols and types

    def apply_intake(self, slug: str, *, notes: str = "", symbols: str = "", types: str = "",
                     refs: str = "", trace: str = "", libraries: str = "", log=print) -> dict:
        """Apply the optional starting context from the import screen. A bad optional file is reported, never
        allowed to fail the import itself."""
        proj = self._project(slug)
        cfg = self.cfg(proj)
        analysis = self.is_analysis(proj)
        warnings: list[str] = []
        applied: dict[str, object] = {}

        text = notes.strip()[:4000]
        if refs.strip():
            text = (text + ("\n" if text else "") + "Reference source folder: " + refs.strip())[:4000]
        if text:
            self.set_instructions(slug, text)
            applied["instructions"] = True

        if symbols.strip() and not analysis:
            try:
                applied["symbols"] = self.import_debug_info(slug, symbols.strip(), log=log)
            except Exception as e:
                warnings.append(f"symbols: {e}")
        if types.strip() and not analysis:
            try:
                path = Path(types.strip()).expanduser()
                if not path.is_absolute():
                    path = Path(proj["root"]) / path
                body = path.read_text(encoding="utf-8", errors="replace")
                if not body.strip():
                    raise ValueError("empty type file")
                agent, _ = self.local_agent("intake")
                res = self.edit_context(agent, slug, "", "\n/* Types supplied at import: " +
                                        path.name.replace("*/", "") + " */\n" + body,
                                        f"intake types from {path.name}")
                if res.startswith("✅"):
                    applied["types"] = True
                else:
                    warnings.append("types: " + res)
            except Exception as e:
                warnings.append(f"types: {e}")
        if trace.strip() and not analysis:
            try:
                applied["trace"] = self.import_trace(slug, trace.strip(), log=log)
            except Exception as e:
                warnings.append(f"trace: {e}")
        if libraries.strip() and not analysis:
            names = [n.strip() for n in re.split(r"[,;\s]+", libraries) if n.strip()]
            n = self.classify_library(slug, names=names, log=log)
            applied["libraries"] = n
        self._syms.pop(proj["id"], None)
        if warnings:
            log("starting context: " + "; ".join(warnings))
        return {"applied": applied, "warnings": warnings}

    _AUTO_FUNCTION = re.compile(r"^(?:sub|func|FUN|loc|D|STR|unk|j|off)_[0-9A-Fa-f]{4,}$")

    def intake_report(self, slug: str) -> dict:
        """What the import already knows, in one place: identity, compiler, debug names, code, data, imports,
        strings, trace and the questions still open. Written to INTAKE.md so agents read it instead of rediscovering."""
        proj = self._project(slug)
        cfg = self.cfg(proj)
        kind = cfg.get("kind") or "rom"
        rom = cfg.get("rom") or {}
        compiler = cfg.get("compiler") or {}
        debug = cfg.get("debug") or {}
        target = cfg.get("target") or {}
        now = time.time()
        if kind == "analysis":
            agg = self.store.one("SELECT COUNT(*) AS total, SUM(status='matched') AS matched, "
                                 "SUM(size) AS bytes FROM functions WHERE project_id=?", proj["id"])
            counts = cfg.get("counts") or {}
            segments = cfg.get("segments") or []
            issues = []
            if not agg["total"]:
                issues.append("no procedures were listed: add tasks or open the target with another REA tool")
            summary = (f"{agg['total'] or 0} work items · {agg['matched'] or 0} analyzed · "
                       f"{target.get('format') or 'file'} {target.get('architecture') or ''}").strip()
            lines = [f"# Intake report: {proj['name']}", "", f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} "
                     f"for project `{proj['slug']}`.", "", "## Target",
                     f"- file: `{target.get('path') or ''}`",
                     f"- format: {target.get('format') or 'file'} · architecture: {target.get('architecture') or 'unknown'}",
                     f"- provider: {cfg.get('provider') or 'auto'}",
                     f"- work items: {agg['total'] or 0} · analyzed: {agg['matched'] or 0} · "
                     f"bytes: {agg['bytes'] or 0}"]
            counts = cfg.get("counts") or {}
            if counts:
                lines.append("- REA inventory: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
            if segments:
                lines += ["", "## Segments"]
                lines += [f"- `{s.get('name') or '?'}` at 0x{int(s.get('vram') or 0):X}" for s in segments[:30]]
            lines += ["", "## How to use this", "REA reads this target. Claim work items, use rea_tool for a deeper "
                      "look, and save findings with complete_function.", ""]
            if issues:
                lines += ["## What is still unknown", *[f"- {i}" for i in issues], ""]
            return {"slug": slug, "kind": kind, "title": proj["name"], "generated_at": now, "summary": summary,
                    "markdown": "\n".join(lines), "path": str(Path(proj["root"]) / "INTAKE.md")}
        if kind == "fork":
            return {"slug": slug, "kind": kind, "title": proj["name"], "generated_at": now,
                    "summary": "a fork already has its project's source and symbols", "markdown": "", "path": ""}
        agg = self.store.one(
            "SELECT COUNT(*) AS total, SUM(status='library') AS library, SUM(status='matched') AS matched, "
            "SUM(size) AS bytes, SUM(n_insns) AS insns, SUM(hits) AS hits, SUM(hits>0) AS traced "
            "FROM functions WHERE project_id=?", proj["id"])
        funcs = self.store.all("SELECT name, vram, size, n_insns, status FROM functions WHERE project_id=? "
                               "ORDER BY n_insns DESC", proj["id"])
        syms = self.store.all("SELECT name, address, size, kind, preview FROM symbols WHERE project_id=?", proj["id"])
        named = [f for f in funcs if not self._AUTO_FUNCTION.match(f["name"]) and f["status"] != "library"]
        imports = []
        seen_imports = set()
        for sym in syms:
            if not sym["name"].startswith("__imp_"):
                continue
            name = sym["name"][6:]
            if name and name not in seen_imports:
                seen_imports.add(name)
                imports.append(name)
        strings = [s for s in syms if s["kind"] == "string" or s["name"].startswith("STR_")]
        strings.sort(key=lambda s: (s["size"] or 0), reverse=True)
        data = [s for s in syms if s["kind"] != "func" and s["kind"] != "string"
                and not s["name"].startswith(("STR_", "__imp_"))]
        data.sort(key=lambda s: (s["size"] or 0), reverse=True)
        entry = rom.get("entrypoint") or 0
        entry_rows = [f for f in funcs if entry and f["vram"] == entry]
        sections = cfg.get("segments") or []
        issues = []
        tc = toolchains.get(compiler.get("toolchain") or "")
        if kind == "rom" and not (agg["total"] or 0):
            issues.append("no functions were found")
        if tc and not toolchains.installed(tc.id):
            issues.append(f"{tc.name} is not installed, so nothing can be compiled yet (Compilers & tools)")
        if kind == "rom" and cfg.get("platform") in X86_PLATFORMS and not debug:
            issues.append("no debug information was shipped: names start as sub_/FUNC_ and types are recovered from code, strings, imports and agents")
        if cfg.get("packed"):
            issues.append("the program looks packed (UPX): unpack it before trusting function boundaries")
        if rom.get("matchable") is False:
            issues.append(f"{rom.get('build_label') or 'this language'} cannot be rebuilt as C/C++; inspect and annotate it instead")
        if not (agg["traced"] or 0):
            issues.append("no runtime trace: hot functions and call order are unknown")
        if funcs and len(named) < max(1, len(funcs) // 20):
            issues.append("almost every function still has an automatic name")
        summary = (f"{agg['total'] or 0} functions · {agg['library'] or 0} library · {len(data)} data · "
                   f"{len(strings)} strings · {len(imports)} imports" +
                   (f" · {agg['traced']} traced ({agg['hits']} hits)" if agg["traced"] else ""))
        markdown = self._intake_markdown(proj, cfg, rom, compiler, debug, target, agg, funcs, named, imports,
                                         strings, data, entry_rows, sections, issues)
        markdown += self._xref_markdown(proj, funcs, syms)
        markdown += self._cxx_markdown(syms)
        groups, unclassified = self._subsystem_groups(proj, funcs, syms)
        if groups or unclassified:
            markdown += self._subsystem_markdown(groups, unclassified)
        markdown += ("## How to use this\n"
                     "This report is generated from the import, not from guesses. Read it before claiming functions; "
                     "use `read_file` for source files, `get_context` for context.h, `search_facts` for a name, "
                     "string, API or address, and `list_subsystems` for a starting area. The target is the final "
                     "judge: compile and diff.\n")
        return {"slug": slug, "kind": kind, "title": proj["name"], "generated_at": now, "summary": summary,
                "markdown": markdown, "path": str(Path(proj["root"]) / "INTAKE.md")}

    def search_facts(self, slug: str, query: str, limit: int = 40) -> str:
        """Search the import's index: function names, symbols, strings, imported APIs and addresses, with the
        callers of every symbol. One tool call replaces a name search followed by xrefs on each hit."""
        proj = self._project(slug)
        q = (query or "").strip()
        if not q:
            return "Give a name, part of a string, an API, or an address (0x140001000)."
        limit = max(1, min(int(limit or 40), 200))
        pid = proj["id"]
        low = q.lower()
        functions = self.store.all(
            "SELECT name, vram, size, n_insns, status FROM functions WHERE project_id=? "
            "AND instr(lower(name), ?) > 0 ORDER BY status='open', n_insns DESC LIMIT ?", pid, low, limit)
        symbols = self.store.all(
            "SELECT name, address, size, kind, preview FROM symbols WHERE project_id=? "
            "AND (instr(lower(name), ?) > 0 OR instr(lower(coalesce(preview,'')), ?) > 0) LIMIT ?",
            pid, low, low, limit)
        try:
            graph = self.xrefs(proj)
        except Exception:
            graph = {"called_by": {}, "calls": {}, "used_by": {}, "uses": {}}
        by_addr = {int(f["vram"]): f["name"] for f in self.store.all(
            "SELECT name, vram FROM functions WHERE project_id=? AND vram IS NOT NULL", pid)}
        lines = [f'Facts matching "{q}"']
        if functions:
            lines.append(f"Functions ({len(functions)}):")
            for r in functions:
                callers = len(graph["called_by"].get(int(r["vram"]), ())) if r["vram"] is not None else 0
                callees = len(graph["calls"].get(int(r["vram"]), ())) if r["vram"] is not None else 0
                lines.append(f"- `{r['name']}` at 0x{int(r['vram'] or 0):X} — {r['status']}, "
                             f"{r['n_insns']} instructions, {r['size']} bytes, {callers} callers, {callees} callees")
        if symbols:
            lines.append(f"Symbols ({len(symbols)}):")
            for r in symbols:
                users = graph["used_by"].get(int(r["address"] or 0), ())
                who = ", ".join(f"`{by_addr[a]}`" for a in sorted(users)[:8] if a in by_addr)
                if len(users) > 8:
                    who += f" +{len(users)-8}"
                detail = f" ({r['kind']}, {r['size']} bytes" + (f": {r['preview']}" if r["preview"] else "") + ")"
                lines.append(f"- `{r['name']}` at 0x{int(r['address'] or 0):X}{detail}"
                             + (f" — used by {who}" if who else ""))
        # An address is often what an agent has, not a name.
        try:
            addr = int(q, 0)
        except ValueError:
            addr = None
        if addr is not None:
            fn = self.store.one("SELECT name, vram, size, n_insns, status FROM functions WHERE project_id=? "
                                "AND vram<=? AND vram+coalesce(size,0)>? ORDER BY vram DESC LIMIT 1", pid, addr, addr)
            if fn:
                lines.append(f"Address 0x{addr:X}: inside `{fn['name']}` at 0x{int(fn['vram'] or 0):X} "
                             f"({fn['status']}, {fn['n_insns']} instructions)")
            sym = self.store.one("SELECT name, address, size, kind, preview FROM symbols WHERE project_id=? "
                                 "AND address=? LIMIT 1", pid, addr)
            if sym:
                lines.append(f"Address 0x{addr:X}: `{sym['name']}` ({sym['kind']}, {sym['size']} bytes)"
                             + (f": {sym['preview']}" if sym["preview"] else ""))
        if len(lines) == 1:
            lines.append("Nothing matched. Try a shorter fragment, an API name, a string, or an address.")
        return "\n".join(lines)

    def _subsystem_groups(self, proj, funcs=None, syms=None):
        """Function vram -> primary subsystem, scored by the imported APIs and strings it references, plus the
        number of unclassified functions. Hints for the first split, not a claim about every function."""
        pid = proj["id"]
        funcs = [f for f in (funcs if funcs is not None else self.store.all(
            "SELECT name, vram, size, n_insns, status FROM functions WHERE project_id=?", pid))
            if f["status"] != "library"]
        syms = syms if syms is not None else self.store.all(
            "SELECT name, address, size, kind, preview FROM symbols WHERE project_id=?", pid)
        by_addr = {int(f["vram"]): f for f in funcs if f["vram"] is not None}
        sym_at = {}
        for s in syms:
            sym_at[int(s["address"] or 0)] = s
        try:
            graph = self.xrefs(proj)
        except Exception:
            return {}, set()
        scores = {}
        def hint(label):
            text = str(label or "").lower()
            for tag, words in SUBSYSTEM_HINTS:
                if any(w in text for w in words):
                    return tag
            return None
        for caller, addrs in graph["uses"].items():
            if caller not in by_addr:
                continue
            for addr in addrs:
                s = sym_at.get(int(addr))
                if not s:
                    continue
                label = s["name"][6:] if s["name"].startswith("__imp_") else (
                    s["preview"] if s["kind"] == "string" and s["preview"] else s["name"])
                tag = hint(label)
                if tag:
                    scores.setdefault(caller, {}).setdefault(tag, 0)
                    scores[caller][tag] += 1
        for caller, callees in graph["calls"].items():
            if caller not in by_addr:
                continue
            for callee in callees:
                other = by_addr.get(int(callee))
                if not other:
                    continue
                tag = hint(other["name"])
                if tag:
                    scores.setdefault(caller, {}).setdefault(tag, 0)
                    scores[caller][tag] += 1
        groups = {}
        for vram, tags in scores.items():
            tag = max(tags, key=tags.get)
            groups.setdefault(tag, []).append(by_addr[vram])
        unclassified = [f for f in funcs if int(f["vram"] or 0) not in scores]
        return groups, unclassified

    def subsystem_text(self, slug: str, limit: int = 12) -> str:
        """The subsystem map as text for an agent: where to start looking, not an authoritative taxonomy."""
        proj = self._project(slug)
        if self.is_analysis(proj):
            return "Subsystem hints are built from imports and strings in a matching project; analysis projects use REA."
        groups, unclassified = self._subsystem_groups(proj)
        if not groups and not unclassified:
            return "No functions to group yet."
        lines = ["Subsystem hints (from imported APIs and strings; verify before relying on one):"]
        for tag, rows in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:max(1, int(limit or 12))]:
            rows = sorted(rows, key=lambda f: (f["n_insns"] or 0), reverse=True)
            lines.append(f"### {tag} — {len(rows)} functions")
            lines += [f"- `{f['name']}` at 0x{int(f['vram'] or 0):X} ({f['n_insns']} instructions, {f['status']})"
                      for f in rows[:10]]
            if len(rows) > 10:
                lines.append(f"- … {len(rows)-10} more")
        if unclassified:
            lines.append(f"### unclassified — {len(unclassified)} functions")
            lines += [f"- `{f['name']}` at 0x{int(f['vram'] or 0):X}" for f in unclassified[:10]]
            if len(unclassified) > 10:
                lines.append(f"- … {len(unclassified)-10} more")
        return "\n".join(lines)

    def _cxx_markdown(self, syms) -> str:
        """C++ vtables and RTTI that survived as symbols; says plainly that stripped binaries need fingerprints."""
        v = sorted((s for s in syms if str(s["name"]).startswith(("??_7", "_ZTV"))),
                   key=lambda s: int(s["address"] or 0))
        r = sorted((s for s in syms if str(s["name"]).startswith(("??_R", "_ZTI", "_ZTS", ".?AV"))),
                   key=lambda s: int(s["address"] or 0))
        if not v and not r:
            return ""
        lines = ["## C++ vtables and RTTI", "Present as symbols; use them to recover classes and virtual calls."]
        if v:
            lines += [f"- vtable: `{s['name']}` at 0x{int(s['address'] or 0):X} ({s['size']} bytes)" for s in v[:30]]
            if len(v) > 30:
                lines.append(f"- … {len(v)-30} more vtables")
        if r:
            lines += [f"- RTTI: `{s['name']}` at 0x{int(s['address'] or 0):X}" for s in r[:30]]
            if len(r) > 30:
                lines.append(f"- … {len(r)-30} more RTTI records")
        lines.append("")
        return "\n".join(lines)

    def _xref_markdown(self, proj, funcs, syms) -> str:
        """The names agents would otherwise look up one by one: most-called functions, and which functions use
        each imported API, string and data object."""
        try:
            graph = self.xrefs(proj)
        except Exception:
            return ""
        by_addr = {int(f["vram"]): f["name"] for f in funcs if f["vram"] is not None}
        def labels(addrs, n=6):
            names = [by_addr.get(int(a), f"0x{int(a):X}") for a in sorted(addrs) if int(a) in by_addr]
            return ", ".join(f"`{x}`" for x in names[:n]) + (f" +{len(names)-n}" if len(names) > n else "")
        called = sorted(((len(v), int(k), by_addr.get(int(k), f"0x{int(k):X}")) for k, v in graph["called_by"].items()),
                        reverse=True)[:15]
        imports = []
        strings = []
        data = []
        for s in syms:
            addr = int(s["address"] or 0)
            users = graph["used_by"].get(addr)
            if not users:
                continue
            name = s["name"]
            if name.startswith("__imp_"):
                imports.append((len(users), name[6:], users))
            elif s["kind"] == "string" or name.startswith("STR_"):
                strings.append((len(users), s["preview"] or name, users))
            elif s["kind"] != "func":
                data.append((len(users), name, users))
        imports.sort(key=lambda r: r[0], reverse=True)
        strings.sort(key=lambda r: r[0], reverse=True)
        data.sort(key=lambda r: r[0], reverse=True)
        lines = []
        if called:
            lines += ["## Most-called functions", *[f"- `{name}` — {n} caller{'s' if n != 1 else ''}"
                                                    for n, _addr, name in called], ""]
        if imports:
            lines += ["## Imported APIs and their callers", *[f"- `{name}` — {n} function{'s' if n != 1 else ''}: "
                                                               f"{labels(users)}" for n, name, users in imports[:30]], ""]
        if strings:
            lines += ["## Strings and their callers", *[f"- \"{str(text)[:100]}\" — {n} function{'s' if n != 1 else ''}: "
                                                         f"{labels(users)}" for n, text, users in strings[:25]], ""]
        if data:
            lines += ["## Data objects and their callers", *[f"- `{name}` — {n} function{'s' if n != 1 else ''}: "
                                                              f"{labels(users)}" for n, name, users in data[:20]], ""]
        return "\n".join(lines)

    @staticmethod
    def _subsystem_markdown(groups, unclassified) -> str:
        lines = ["## Subsystem hints", "From imported APIs and strings; a starting point, not a proof."]
        for tag, rows in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:12]:
            rows = sorted(rows, key=lambda f: (f["n_insns"] or 0), reverse=True)
            lines.append(f"### {tag} — {len(rows)} functions")
            lines += [f"- `{f['name']}` at 0x{int(f['vram'] or 0):X} ({f['n_insns']} instructions, {f['status']})"
                      for f in rows[:8]]
            if len(rows) > 8:
                lines.append(f"- … {len(rows)-8} more")
        if unclassified:
            lines.append(f"### unclassified — {len(unclassified)} functions")
            lines += [f"- `{f['name']}` at 0x{int(f['vram'] or 0):X}" for f in unclassified[:8]]
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _intake_markdown(proj, cfg, rom, compiler, debug, target, agg, funcs, named, imports, strings, data,
                         entry_rows, sections, issues) -> str:
        """A readable report, not JSON: the same facts an analyst would write on the first page."""
        def size(n):
            n = int(n or 0)
            return f"{n // (1 << 20)} MiB" if n >= 1 << 20 else f"{n / 1024:.1f} KiB" if n >= 1024 else f"{n} B"
        def esc(s):
            return str(s or "").replace("|", "\\|").replace("\n", " ")[:160]
        lines = [f"# Intake report: {proj['name']}", "",
                 f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} for project `{proj['slug']}`.", ""]
        if target:
            lines += ["## Target", f"- file: `{target.get('path') or ''}`",
                      f"- format: {target.get('format') or 'file'} · architecture: {target.get('architecture') or 'unknown'}",
                      f"- provider: {cfg.get('provider') or 'auto'}", ""]
            counts = cfg.get("counts") or {}
            if counts:
                lines += ["- REA inventory: " + ", ".join(f"{k} {v}" for k, v in counts.items())]
        else:
            lines += ["## Identity", f"- file: `{rom.get('file') or ''}`",
                      f"- platform: {cfg.get('platform') or 'unknown'} · architecture: {proj['arch']} · "
                      f"{'big endian' if proj['big_endian'] else 'little endian'}",
                      f"- title: {rom.get('title') or proj['name']} · game code: {rom.get('game_code') or 'none'} · "
                      f"region: {rom.get('region') or 'unknown'}",
                      f"- size: {size(rom.get('size'))} · SHA-1: `{rom.get('sha1') or ''}`",
                      f"- entry point: 0x{int(rom.get('entrypoint') or 0):X}" +
                      (f" · image base: 0x{int(rom.get('image_base') or 0):X}" if rom.get("image_base") else ""), ""]
        tc_name = ""
        if compiler:
            tc = toolchains.get(compiler.get("toolchain") or "")
            tc_name = tc.name if tc else (compiler.get("toolchain") or "")
            flags = " ".join(compiler.get("flags") or [])
            lines += ["## Compiler", f"- toolchain: {tc_name or 'none'}",
                      f"- source language: {rom.get('language_guess') or source_language(compiler.get('toolchain') or '')}",
                      f"- detected: {rom.get('build_label') or rom.get('compiler_guess') or 'unknown'}"
                      + (f" · version {rom.get('compiler_version')}" if rom.get("compiler_version") else ""),
                      f"- flags: `{flags or '(none)'}`"]
            if rom.get("suggested_flags"):
                lines.append(f"- inferred flags: `{' '.join(rom['suggested_flags'])}`")
            evidence = rom.get("flag_evidence") or []
            if evidence:
                lines.append("- evidence: " + "; ".join(str(e) for e in evidence[:6]))
            if tc and not toolchains.installed(tc.id):
                lines.append("- **not installed**: install it in Compilers & tools to compile candidates")
            lines.append("")
        if debug:
            lines += ["## Debug information", f"- source: `{debug.get('source') or ''}`",
                      f"- names: {debug.get('symbols', 0)} · types: {debug.get('types', 0)}"]
            if cfg.get("context", {}).get("file") or debug.get("header"):
                lines.append("- the debug header is part of context.h (unless it failed to compile)")
            lines.append("")
        lines += ["## Code", f"- functions: {agg['total'] or 0} ({agg['library'] or 0} library/CRT, "
                  f"{agg['matched'] or 0} matched) · {size(agg['bytes'])} · {agg['insns'] or 0} instructions",
                  f"- named: {len(named)} · automatic names: {max(0, (agg['total'] or 0) - (agg['library'] or 0) - len(named))}",
                  f"- data objects: {len(data)} · strings: {len(strings)} · imports: {len(imports)}",
                  f"- trace: {agg['traced'] or 0} functions, {agg['hits'] or 0} hits" +
                  ("" if agg["traced"] else " (none imported)"), ""]
        if entry_rows:
            lines += ["## Entry point", *[f"- `{r['name']}` at 0x{int(r['vram'] or 0):X} ({r['n_insns']} instructions)"
                                          for r in entry_rows[:6]], ""]
        if named:
            lines += ["## Named functions (first 20)", *[f"- `{r['name']}` at 0x{int(r['vram'] or 0):X} — "
                                                       f"{r['size']} bytes, {r['n_insns']} instructions, {r['status']}"
                                                       for r in named[:20]], ""]
        if funcs:
            lines += ["## Largest functions", "| address | function | bytes | instructions | status |",
                      "|---|---|---:|---:|---|",
                      *[f"| 0x{int(r['vram'] or 0):X} | `{esc(r['name'])}` | {r['size']} | {r['n_insns']} | {r['status']} |"
                        for r in funcs[:15]], ""]
        if imports:
            lines += ["## Imported APIs (first 40)", *[f"- `{esc(n)}`" for n in imports[:40]], ""]
        if strings:
            lines += ["## Strings (largest 20)", *[f"- 0x{int(s['address'] or 0):X} ({s['size']} B): {esc(s['preview'])}"
                                                  for s in strings[:20] if s["preview"]], ""]
        if data:
            lines += ["## Data objects (largest 15)", "| address | name | bytes | kind | preview |",
                      "|---|---|---:|---|---|",
                      *[f"| 0x{int(s['address'] or 0):X} | `{esc(s['name'])}` | {s['size']} | {s['kind']} | {esc(s['preview'])} |"
                        for s in data[:15]], ""]
        if sections:
            lines += ["## Sections", *[f"- `{s.get('name') or '?'}` at 0x{int(s.get('vram') or 0):X} "
                                       f"(file 0x{int(s.get('rom_start') or 0):X}..0x{int(s.get('rom_end') or 0):X})"
                                       for s in sections[:30]], ""]
        if issues:
            lines += ["## What is still unknown", *[f"- {i}" for i in issues], ""]
        return "\n".join(lines)

    def write_intake(self, slug: str, log=print) -> dict:
        """Write INTAKE.md beside the project and remember it, so every agent can read the import's findings."""
        proj = self._project(slug)
        report = self.intake_report(slug)
        if not report["markdown"] or self.cfg(proj).get("kind") == "fork":
            return report
        path = Path(proj["root"]) / "INTAKE.md"
        path.write_text(report["markdown"], encoding="utf-8")
        self._update_cfg(slug, lambda cfg: cfg.__setitem__("intake", {"file": "INTAKE.md", "generated_at": report["generated_at"]}))
        report["path"] = str(path)
        log(f"intake report: {path.name} ({report['summary']})")
        return report

    def intake_line(self, slug: str) -> str:
        """The one line every agent prompt and brief gets, pointing at the report instead of rediscovering it."""
        proj = self._project(slug)
        cfg = self.cfg(proj)
        if not cfg.get("intake"):
            return ""
        path = Path(proj["root"]) / (cfg["intake"].get("file") or "INTAKE.md")
        return (f"Intake report (facts already extracted at import; read it first with read_file): {path}. "
                f"It lists the target, compiler and flags, debug names/types, function and data inventory, imports, "
                f"strings and what is still unknown.")

    def import_debug_info(self, slug: str, path: str = "", log=print) -> dict:
        """Merge a PDB/DWARF/MAP/symbol_addrs file into an existing project: names replace automatic ones,
        data names are added, and types are appended to the shared header (regression-tested when it has matches)."""
        proj = self._project(slug)
        cfg = self.cfg(proj)
        if cfg.get("kind") == "fork":
            raise NetworkError("debug symbol import is for ROM and PC projects; a fork already has its project's symbols")
        root = Path(proj["root"])
        target = root / (cfg.get("rom", {}).get("program") or cfg.get("rom", {}).get("file") or "")
        image = None
        data = None
        if cfg.get("platform") in X86_PLATFORMS and target.is_file():
            data = target.read_bytes()
            from ..rom import elfexe
            image = (elfexe if cfg.get("platform") == "linux" else pe).read(data, target.name)
        if path.strip():
            p = Path(path.strip()).expanduser()
            if not p.is_absolute():
                p = root / p
            if not p.is_file():
                raise NetworkError(f"no debug file at {p}")
            info = debuginfo.read(p, image=image)
        else:
            info = debuginfo.discover(target, data, image=image)
            if info is None:
                raise NetworkError(f"no PDB, DWARF, MAP or symbol_addrs.txt found for {target}")
        if not info.symbols and not info.functions and not info.header:
            raise NetworkError(f"{info.source} has no symbols or types this reader understands")

        rows = self.store.all("SELECT * FROM functions WHERE project_id=? AND vram IS NOT NULL", proj["id"])
        by_addr = {int(r["vram"]): r for r in rows if r["vram"]}
        symbols = self.store.all("SELECT * FROM symbols WHERE project_id=?", proj["id"])
        taken = {s["name"] for s in symbols} | {r["name"] for r in rows}
        # PDB/DWARF have explicit functions; a MAP or symbol_addrs.txt only has names. A name at a split
        # function's address is a function name there, whatever the file called it.
        candidates: dict[tuple[int, str], object] = {}
        for meta in info.functions:
            if meta.name:
                candidates.setdefault((meta.address, meta.name), meta)
        for sym in info.symbols:
            if sym.kind == "func" or sym.address in by_addr:
                candidates.setdefault((sym.address, sym.name), debuginfo.DebugFunction(sym.name, sym.address, sym.size))
        renames: list[tuple[str, str]] = []
        for (address, name), _meta in sorted(candidates.items()):
            row = by_addr.get(address)
            if row is None or not name or not IDENT.match(name) or name in taken:
                continue
            if row["name"] == name:
                continue
            if not (AUTO_NAME.match(row["name"]) or row["name"].startswith("sub_")):
                continue  # a name a person chose wins over a debug symbol
            renames.append((row["name"], name))
            taken.discard(row["name"])
            taken.add(name)

        added = 0
        now = time.time()
        with self.store.tx() as db:
            for old, new in renames:
                row = db.execute("SELECT id, asm, matched_source, best_source FROM functions WHERE project_id=? AND name=?",
                                 (proj["id"], old)).fetchone()
                if row is None:
                    continue
                db.execute("UPDATE functions SET name=? WHERE id=?", (new, row["id"]))
                asm = (row["asm"] or "").replace(f"glabel {old}", f"glabel {new}").replace(f"endlabel {old}", f"endlabel {new}")
                db.execute("UPDATE functions SET asm=? WHERE id=?", (asm, row["id"]))
                word = re.compile(rf"\b{re.escape(old)}\b")
                for col in ("matched_source", "best_source"):
                    if row[col]:
                        db.execute(f"UPDATE functions SET {col}=? WHERE id=?", (word.sub(new, row[col]), row["id"]))
                db.execute("UPDATE symbols SET name=? WHERE project_id=? AND name=?", (new, proj["id"], old))
            for sym in info.symbols:
                if not sym.name or not IDENT.match(sym.name):
                    continue
                row = db.execute("SELECT address FROM symbols WHERE project_id=? AND name=?",
                                 (proj["id"], sym.name)).fetchone()
                if row is not None:
                    if row["address"] != sym.address:
                        continue  # don't steal an existing name for another address
                    db.execute("UPDATE symbols SET size=?, kind=?, preview=? WHERE project_id=? AND name=?",
                               (sym.size, sym.kind, sym.preview or None, proj["id"], sym.name))
                else:
                    db.execute("INSERT INTO symbols(project_id,name,address,size,kind,preview) "
                               "VALUES(?,?,?,?,?,?)", (proj["id"], sym.name, sym.address, sym.size, sym.kind,
                                                       sym.preview or None))
                    added += 1
            self._event(db, proj["id"], None, "debug", f"{info.source}: {len(renames)} renamed, {added} new symbols")
        self._syms.pop(proj["id"], None)
        self._xrefs.pop(proj["id"], None)
        self._ops.pop(proj["id"], None)
        self.classify_library(slug, log=log)

        types_added = False
        warning = ""
        if info.header:
            ctx = self._context(proj["id"])
            if info.header.strip() not in (ctx["header"] if ctx else ""):
                agent, _ = self.local_agent("debuginfo")
                try:
                    res = self.edit_context(agent, slug, "", "\n/* Debug information imported from " +
                                            info.source.replace("*/", "") + " */\n" + info.header,
                                            "import debug types")
                    types_added = res.startswith("✅")
                    if not types_added:
                        warning = res
                except NetworkError as e:
                    warning = str(e)
        self._update_cfg(slug, lambda c: c.__setitem__("debug", {
            "source": info.source, "symbols": len(info.symbols), "types": len(info.types),
            "header": info.header, "imported_at": now}))
        log(f"{info.source}: {len(renames)} functions renamed, {added} symbols added, "
            f"{len(info.types)} types{' imported' if types_added else ''}")
        return {"source": info.source, "renamed": len(renames), "symbols": added, "types": len(info.types),
                "types_added": types_added, "warning": warning}

    def export_debug_info(self, slug: str) -> dict:
        """Write portable symbol and type files into the project folder."""
        proj = self._project(slug)
        cfg = self.cfg(proj)
        root = Path(proj["root"])
        rows = self.store.all("SELECT name,address,size,kind FROM symbols WHERE project_id=? ORDER BY address", proj["id"])
        syms = [Symbol(r["name"], int(r["address"]), int(r["size"] or 0), r["kind"] or "data") for r in rows]
        sym_path = root / "symbol_addrs.txt"
        sym_path.write_text(debuginfo.symbol_addrs_text(syms), encoding="utf-8")
        debug = cfg.get("debug") or {}
        header = debug.get("header") or "/* No debug types were imported for this project. */\n"
        type_path = root / "debug_types.h"
        type_path.write_text(header, encoding="utf-8")
        json_path = root / "debug_symbols.json"
        json_path.write_text(debuginfo.symbols_json(syms), encoding="utf-8")
        return {"symbols": len(syms), "types": debug.get("types", 0), "symbol_addrs": str(sym_path),
                "types_header": str(type_path), "json": str(json_path)}

    def classify_library(self, slug: str, log=print, names=()) -> int:
        """Mark open functions whose names are CRT/runtime/library code, including projects imported before this.
        Matched or hand-written functions are never touched. `names` are libraries the user already knows."""
        proj = self._project(slug)
        rows = self.store.all("SELECT id, name, meta FROM functions WHERE project_id=? AND status='open'",
                              proj["id"])
        found = []
        wanted = {n.lower() for n in names if n}
        for row in rows:
            kind = library.kind(row["name"])
            if not kind and wanted and any(w in row["name"].lower() for w in wanted):
                kind = "known library"
            if kind:
                meta = json.loads(row["meta"] or "{}")
                meta["library"] = kind
                found.append((json.dumps(meta), row["id"]))
        if found:
            with self.store.tx() as db:
                db.executemany("UPDATE functions SET status='library', meta=? WHERE id=? AND status='open'", found)
                db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
                           (proj["id"], None, "library", f"{len(found)} library/CRT functions skipped", time.time()))
            log(f"{len(found)} library/CRT functions marked and skipped")
        return len(found)

    def compare_version(self, slug: str, path: str) -> dict:
        """Compare the project's own target with another build (a patch, demo or port)."""
        proj = self._project(slug)
        cfg = self.cfg(proj)
        if cfg.get("kind") == "fork":
            raise NetworkError("compare versions on a ROM or PC project, not on a fork")
        if cfg.get("platform") not in X86_PLATFORMS:
            raise NetworkError("version comparison currently covers Windows and Linux x86 programs")
        root = Path(proj["root"])
        target = root / (cfg.get("rom", {}).get("program") or cfg.get("rom", {}).get("file") or "")
        if not target.is_file():
            raise NetworkError(f"the project's target is missing: {target}")
        other = Path(path).expanduser()
        if not other.is_absolute():
            other = root / other
        if not other.is_file():
            raise NetworkError(f"no program at {other}")
        if other.resolve() == target.resolve():
            raise NetworkError("that's the project's own target; choose another version")
        names = {int(r["vram"]): r["name"] for r in self.store.all(
            "SELECT name, vram FROM functions WHERE project_id=? AND vram IS NOT NULL", proj["id"])}
        return bincompare.compare_paths(target, other, old_names=names)

    def _community_layout(self, data: bytes | Path, name: str = "") -> Path | None:
        """The file, when the game starts as a community-layout project: a GameCube/Wii program (DOL) or disc image
        (dtk-template), or a DS ROM (ds-decomp). Bytes are saved to a file first."""
        from ..forks import scratch_dsd, scratch_dtk

        head = Path(data).open("rb").read(0x440) if isinstance(data, (str, Path)) else bytes(data[:0x440])
        small = Path(data).read_bytes() if isinstance(data, (str, Path)) and Path(data).stat().st_size < 64 << 20 else data
        nds = scratch_dsd.is_nds(head)
        if not nds and scratch_dtk.disc_kind(head) is None and not (isinstance(small, (bytes, bytearray))
                                                                   and scratch_dtk.is_dol(small)):
            return None
        if isinstance(data, (str, Path)):
            return Path(data)
        uploads = self.workspace / ".decomp" / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        path = uploads / (Path(name).name or ("game.nds" if nds else "main.dol" if scratch_dtk.is_dol(data) else "game.iso"))
        path.write_bytes(data)
        return path

    @staticmethod
    def _asm_source(fn: split.RomFunction) -> str:
        out = [f"glabel {fn.name}"]
        for ln in fn.lines:
            if ln.vram in fn.labels and ln.vram != fn.vram:
                out.append(f".L{ln.vram:08X}:")
            out.append(f"/* {ln.rom:X} {ln.vram:08X} {ln.word:08X} */  {ln.mnemonic:<10} {ln.operands}".rstrip())
        out.append(f"endlabel {fn.name}")
        return "\n".join(out)

    @staticmethod
    def _parse_asm(name: str, text: str, segment: str) -> split.RomFunction:
        lines, labels = [], set()
        for raw in text.splitlines():
            m = split._INSN.match(raw)
            if m:
                rom, vram, word, mnem, ops = m.groups()
                lines.append(split.AsmLine(int(rom, 16), int(vram, 16), int(word, 16), mnem, ops))
                continue
            m = split._LABEL.match(raw)
            if m:
                labels.add(int(m.group(1).lstrip(".L"), 16))
        return split.RomFunction(name, lines[0].vram, lines[0].rom, segment, lines, Path(), labels)

    # ------------------------------------------------------------------ drafts

    def _rea_seed(self, fn, proj) -> str | None:
        """A decompiler draft for Windows targets, through REA when it is set up (see rea.py)."""
        if fn["seed"] is not None:
            return fn["seed"]
        from .. import rea

        text = rea.draft(self.workspace / self.cfg(proj)["rom"]["program"], fn)
        if text:
            with self.store.tx() as db:
                db.execute("UPDATE functions SET seed=? WHERE id=?", (text, fn["id"]))
        return text

    def _seed_for(self, fn, proj) -> str | None:
        """m2c draft, made the first time someone opens the function (imports stay fast)."""
        if self.cfg(proj).get("platform") in X86_PLATFORMS:
            return self._rea_seed(fn, proj)
        if fn["seed"] is not None or not seeds.available():
            return fn["seed"]
        tc = self.cfg(proj)["compiler"]["toolchain"]
        asm = self._asm_text(fn, proj)
        data_asm = None
        if "jtbl_" in fn["asm"]:
            data_asm = "\n".join(self._jtbl_asm(proj, fn))
        ctx = self._context(proj["id"], fn["unit"])
        draft = seeds.generate_from_asm(asm, fn["name"], tc, ctx["header"] if ctx else "", data_asm)
        text = f"/* machine-generated by m2c: a starting point, not a match */\n{draft}" if draft else ""
        with self.store.tx() as db:
            db.execute("UPDATE functions SET seed=? WHERE id=?", (text, fn["id"]))
        return text

    def _jtbl_asm(self, proj, fn) -> list[str]:
        out = [".section .rodata"]
        read = self.reader(proj)
        syms = self.symbols(proj["id"])
        for m in sorted(set(re.findall(r"jtbl_([0-9A-F]{8})", fn["asm"]))):
            addr = int(m, 16)
            sym = syms.by_addr.get(addr)
            size = sym.size if sym and sym.size else 0
            data = read(addr, size) if size else None
            if not data:
                continue
            out.append(f"dlabel {syms.label(addr)}")
            fmt = ">I" if self.cfg(proj).get("big_endian", True) else "<I"
            for (w,) in struct.iter_unpack(fmt, data[:len(data) // 4 * 4]):
                out.append(f".word .L{w:08X}" if fn["vram"] <= w < fn["vram"] + fn["size"] else f".word 0x{w:08X}")
        return out

    def get_context(self, project: str | None, function: str | None = None) -> str:
        self._rom_only(project, "get_context")
        return super().get_context(project, function)

    def _brief(self, fn, agent, header):
        if self.cfg(self.store.one("SELECT config FROM projects WHERE id=?", fn["project_id"])).get("kind") == "fork":
            return self.forks.brief(fn, agent, header)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        if self.is_rom(proj) and fn["status"] != "matched" and not fn["best_source"] and fn["seed"] is None:
            with self._seed_lock:
                self._seed_for(self._function(fn["name"], proj["slug"]), proj)
            fn = self._function(fn["name"], proj["slug"])
        return super()._brief(fn, agent, header)

    # ------------------------------------------------------------------ cross references

    def xrefs(self, proj) -> dict:
        """calls / called_by / uses / used_by, all keyed by address."""
        if proj["id"] in self._xrefs:
            return self._xrefs[proj["id"]]
        funcs = self.store.all("SELECT name, vram, size, relocs FROM functions WHERE project_id=?", proj["id"])
        starts = {f["vram"] for f in funcs}
        calls, called_by, uses, used_by = {}, {}, {}, {}
        # Calls to something not known as a function are not data: R_MIPS_26, or 10, a Thumb call (GBA). On x86
        # those numbers are RIP-relative and absolute data references, so nothing is left out there.
        not_data = () if self.cfg(proj).get("platform") in X86_PLATFORMS else (match.R_MIPS_26, 10)
        for f in funcs:
            for row in json.loads(f["relocs"]):
                off, rtype, addr = row[0], row[1], row[2]
                if f["vram"] <= addr < f["vram"] + f["size"]:
                    continue
                if addr in starts:
                    calls.setdefault(f["vram"], set()).add(addr)
                    called_by.setdefault(addr, set()).add(f["vram"])
                elif rtype not in not_data:
                    uses.setdefault(f["vram"], set()).add(addr)
                    used_by.setdefault(addr, set()).add(f["vram"])
        self._xrefs[proj["id"]] = {"calls": calls, "called_by": called_by, "uses": uses, "used_by": used_by}
        return self._xrefs[proj["id"]]

    def _extra_brief(self, fn, proj) -> list[str]:
        if not self.is_rom(proj):
            return []
        syms = self.symbols(proj["id"])
        x = self.xrefs(proj)
        lines = [""]
        if (facts := self.intake_line(proj["slug"])):
            lines += [facts, ""]
        lines += ["### Where it lives",
                 f"address 0x{fn['vram']:08X}, ROM offset 0x{fn['rom_offset']:X}, segment {fn['unit']}"]
        calls = sorted(x["calls"].get(fn["vram"], ()))
        callers = sorted(x["called_by"].get(fn["vram"], ()))
        if calls:
            lines.append("calls: " + ", ".join(syms.label(a) for a in calls[:30]))
        if callers:
            lines.append("called by: " + ", ".join(syms.label(a) for a in callers[:30]))
        used = sorted(x["uses"].get(fn["vram"], ()))
        if used:
            lines += ["", "### Data it uses (declare what you need as extern in your source, or in context.h)"]
            prev = {r["name"]: r for r in self.store.all("SELECT name, kind, size, preview FROM symbols WHERE project_id=?", proj["id"])}
            for a in used[:40]:
                name, off = syms.name_at(a)
                r = prev.get(name)
                desc = f"{r['kind']}, {r['size']} bytes" if r else "unknown size"
                if r and r["preview"]:
                    desc += f": {r['preview']}"
                lines.append(f"- {syms.label(a)} (0x{a:08X}; {desc})")
        twin = self._twin_lines(proj, fn) if fn["status"] != "matched" else []
        lines += twin
        alike = [] if twin else [(r, sim) for r, sim in self.similar(proj, fn, top=3) if r["status"] == "matched"]
        if alike:
            lines += ["", "### Looks like (already matched; read with get_function)",
                      ", ".join(f"{r['name']} ({sim * 100:.0f}% similar)" for r, sim in alike)]
            r, sim = alike[0]
            src = self.store.one("SELECT matched_source FROM functions WHERE project_id=? AND name=?", proj["id"], r["name"])
            if sim >= 0.8 and src and src["matched_source"] and len(src["matched_source"]) <= 3000:
                # nearly the same code: its matching source is the best starting point there is (saves a tool call)
                lang = source_language(self.cfg(proj)["compiler"]["toolchain"])
                lines += [f"Matching {lang} of {r['name']} ({sim * 100:.0f}% similar): start from this",
                          f"```{'cpp' if lang == 'C++' else 'c'}", src["matched_source"].strip(), "```"]
        if (roots := self.references(proj["slug"])):
            from . import references

            hits = references.search(roots, rf"0x0*{fn['vram']:x}\b")
            if hits != "no matches":
                lines += ["", "### In the reference folders (read_file / search_code for more)",
                          *hits.splitlines()[:12]]
        lines += ["", "Names: use the names shown here (or rename_symbol to give an address a real name). "
                      "Your code is linked at this function's address and must reproduce the ROM bytes exactly."]
        return lines

    def _rom_ops(self, proj) -> dict[tuple[int, int], list[str]]:
        """(vram, size) -> mnemonics of every function, cached (renames keep addresses; splits change sizes)."""
        cache = self._ops.setdefault(proj["id"], {})
        rows = self.store.all("SELECT vram, size, target FROM functions WHERE project_id=? AND target IS NOT NULL", proj["id"])
        live = set()
        for r in rows:
            key = (r["vram"], r["size"])
            live.add(key)
            if key not in cache:
                cache[key] = (similarity.thumb_mnemonics(r["target"], r["vram"] or 0) if proj["arch"] == "arm" else
                              similarity.mips_mnemonics(r["target"], bool(proj["big_endian"]), r["vram"] or 0))
        for key in set(cache) - live:
            del cache[key]
        return cache

    def similar(self, proj, fn, top: int = 5) -> list[tuple[dict, float]]:
        """Functions whose instructions look like `fn`'s, matched ones first: [(row, similarity)]."""
        if fn["target"] is None:
            return []
        ops = self._rom_ops(proj)
        me = (fn["vram"], fn["size"])
        if me not in ops:
            return []
        cands = {f"{v}:{n}": o for (v, n), o in ops.items() if (v, n) != me}
        rows = {(r["vram"], r["size"]): r for r in self.store.all(
            "SELECT name, vram, size, n_insns, status, best_score FROM functions WHERE project_id=?", proj["id"])}
        out = []
        for key, sim in similarity.rank(ops[me], cands, top=top * 2):
            v, n = (int(x) for x in key.split(":"))
            if (v, n) in rows:
                out.append((rows[(v, n)], sim))
        out.sort(key=lambda x: (x[0]["status"] != "matched", -x[1]))
        return out[:top]

    def find_similar(self, project: str | None, function: str, limit: int = 5) -> str:
        if (fork := self.fork_slug(project)):
            return self.forks.find_similar(fork, function, limit)
        proj = self._project(project)
        fn = self._function(function, proj["slug"])
        hits = self.similar(proj, fn, top=max(1, min(int(limit), 15)))
        if not hits:
            return f"No look-alikes found for {fn['name']}."
        lines = [f"Functions that look like {fn['name']}:"]
        for r, sim in hits:
            state = "matched" if r["status"] == "matched" else f"best {r['best_score']}" if r["best_score"] is not None else "not started"
            lines.append(f"- {r['name']}  {sim * 100:.0f}% similar  {state}  ({r['n_insns']} insns, 0x{r['vram']:08X})")
        best = next((r for r, _ in hits if r["status"] == "matched"), None)
        if best is not None:
            src = self.store.one("SELECT matched_source FROM functions WHERE project_id=? AND name=?", proj["id"], best["name"])
            if src and src["matched_source"]:
                lang = source_language(self.cfg(proj)["compiler"]["toolchain"])
                lines += ["", f"Matching {lang} of {best['name']}:", f"```{'cpp' if lang == 'C++' else 'c'}",
                          src["matched_source"].strip()[:4000], "```"]
        return "\n".join(lines)

    # ------------------------------------------------------------------ agent tools for ROMs

    def list_functions(self, project: str | None, status: str = "open", limit: int = 40) -> str:
        if (fork := self.fork_slug(project)):
            return self.forks.list_functions(fork, status, limit)
        proj = self._project(project)
        analysis = self.is_analysis(proj)
        where = "" if status == "all" else " AND f.status=?"
        args = [proj["id"]] + ([] if status == "all" else [status])
        rows = self.store.all(
            f"SELECT f.name, f.vram, f.n_insns, f.status, f.best_score, a.name AS claimed_by FROM functions f "
            f"LEFT JOIN claims c ON c.function_id=f.id LEFT JOIN agents a ON a.id=c.agent_id "
            f"WHERE f.project_id=?{where} ORDER BY f.vram LIMIT ?", *args, limit)
        if not rows:
            return f"No {status} {'work items' if analysis else 'functions'}."
        if analysis:
            return "\n".join(f"- {r['name']}" + (f" @0x{r['vram']:08X}" if r["vram"] else " (task)")
                             + f": {r['status']}" + (f", claimed by {r['claimed_by']}" if r["claimed_by"] else "")
                             for r in rows)
        return "\n".join(f"- {r['name']} @0x{r['vram']:08X}: {r['n_insns']} insns, {r['status']}"
                         + (f", best score {r['best_score']}" if r["best_score"] is not None else "")
                         + (f", claimed by {r['claimed_by']}" if r["claimed_by"] else "") for r in rows)

    def get_function(self, function: str, project: str | None = None, agent: Agent | None = None) -> str:
        fn = self._function(function, project)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        if self.is_analysis(proj):
            return self._analysis_brief(fn, agent, "VIEW")
        return super().get_function(function, project, agent)

    def inspect_binary(self, project: str | None, function: str, what: str = "") -> str:
        """Windows targets: REA's dossier for a function (pseudocode, signature, callers), or decomp.wtf's own
        assembly and cross references when REA isn't installed. Analysis projects: the work item's REA dossier."""
        fn = self._function(function, project)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        if self.is_analysis(proj):
            return self._analysis_brief(fn, None, "VIEW")
        cfg = self.cfg(proj)
        if cfg.get("platform") not in X86_PLATFORMS:
            raise NetworkError("inspect_binary is for Windows and Linux programs: use get_function for this one")
        binary = Path(proj["root"]) / cfg["rom"]["program"]
        syms = self.symbols(proj["id"])
        try:
            from .. import rea

            text = rea.inspect(binary, fn, syms, what)
        except Exception as e:  # REA is optional: never turn a missing analyzer into a failed claim
            text = f"(REA is not available: {e})"
        x = self.xrefs(proj)
        lines = [text, "", "### decomp.wtf's view", self._asm_text(fn, proj)]
        calls = sorted(x["calls"].get(fn["vram"], ()))
        callers = sorted(x["called_by"].get(fn["vram"], ()))
        if calls:
            lines.append("calls: " + ", ".join(syms.label(a) for a in calls[:30]))
        if callers:
            lines.append("called by: " + ", ".join(syms.label(a) for a in callers[:30]))
        return "\n".join(lines)

    def search_binary(self, project: str | None, query: str) -> str:
        """Strings and procedure names in a Windows target: REA's inventories when available, else what
        decomp.wtf knows (symbol and function names). Analysis projects: REA's inventories."""
        proj = self._project(project)
        if self.is_analysis(proj):
            return self.analysis_search(proj["slug"], query)
        cfg = self.cfg(proj)
        if cfg.get("platform") not in X86_PLATFORMS:
            raise NetworkError("search_binary is for Windows and Linux programs")
        try:
            from .. import rea

            return rea.search(Path(proj["root"]) / cfg["rom"]["program"], query, self.symbols(proj["id"]))
        except Exception as e:  # REA is optional
            syms = self.symbols(proj["id"])
            rows = [f"- symbol {s.name} at 0x{s.address:08X}" for s in syms.by_name.values() if query.lower() in s.name.lower()]
            funcs = self.store.all("SELECT name, vram FROM functions WHERE project_id=? AND name LIKE ? LIMIT 40",
                                   proj["id"], f"%{query}%")
            rows += [f"- function {r['name']} at 0x{r['vram']:08X}" for r in funcs]
            return (f"(REA is not available: {e})\n" + "\n".join(rows[:60])) if rows else \
                f"(REA is not available: {e}) decomp.wtf knows no symbol matching {query!r}."

    def read_data(self, project: str | None, what: str, length: int = 64) -> str:
        proj = self._project(project)
        if self.is_analysis(proj):
            return self.analysis_read_data(proj["slug"], what, length)
        self._rom_only(project, "read_data")
        syms = self.symbols(proj["id"])
        m = _ADDRESS.match(what.strip())
        addr = int(m.group(1), 16) if m else syms.resolve(what.strip())
        if addr is None:
            raise NetworkError(f"`{what}` is not an address or a known symbol")
        length = max(4, min(int(length), 512))
        data = self.reader(proj)(addr, length)
        head = f"{syms.label(addr)} at 0x{addr:08X}"
        if data is None:
            sym = syms.by_addr.get(addr)
            if sym and sym.kind == "bss":
                return f"{head}: uninitialized data (.bss), {sym.size} bytes; it starts as zeros at boot."
            return f"{head}: not in a loaded part of the ROM (maybe .bss, or a segment that isn't split yet)."
        out = [head]
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
            out.append(f"  {addr + i:08X}: {chunk.hex(' '):<47}  {text}")
        e = ">" if self.cfg(proj).get("big_endian", True) else "<"
        words = [w for (w,) in struct.iter_unpack(e + "I", data[:len(data) // 4 * 4])]
        ptrs = [f"+0x{4 * i:X}: {syms.label(w)}" for i, w in enumerate(words) if 0x80000400 <= w < 0x80800000]
        if ptrs:
            out.append("words that look like addresses: " + ", ".join(ptrs[:16]))
        floats = [struct.unpack(e + "f", struct.pack(e + "I", w))[0] for w in words[:8]]
        if any(1e-6 < abs(f) < 1e7 for f in floats):
            out.append("as f32: " + ", ".join(f"{f:g}" for f in floats))
        return "\n".join(out)

    def split_function(self, agent: Agent, project: str | None, function: str, at: str, new_name: str = "") -> str:
        self._rom_only(project, "split_function")
        link = self._link(project)
        if link is not None:
            name = self._function(function, project)["name"]
            text = link.call("/collab/split", agent, function=name, at=at, new_name=new_name)
            if text.startswith("✅"):
                link.sync()
            return text
        fn = self._function(function, project)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        if not self.is_rom(proj):
            raise NetworkError("split_function is for ROM projects")
        if self.cfg(proj).get("platform") in X86_PLATFORMS:
            raise NetworkError("split_function isn't needed for PC programs: function boundaries come from the "
                               "executable (.pdata or .eh_frame, its symbol table and call targets)")
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} is matched; it can't be split")
        m = _ADDRESS.match(str(at).strip())
        if not m:
            raise NetworkError("`at` must be an address like 0x80001234")
        addr = int(m.group(1), 16)
        new_name = (new_name or f"func_{addr:08X}").strip()
        syms = self.symbols(proj["id"])
        if not IDENT.match(new_name) or new_name in syms.by_name:
            raise NetworkError(f"`{new_name}` is not a free C identifier")
        if self.cfg(proj).get("platform") == "gba":
            return self._split_gba(agent, proj, fn, addr, new_name, syms)
        rf = self._parse_asm(fn["name"], fn["asm"], fn["unit"])
        try:
            head, tail = split.split_function(rf, addr, new_name)
        except ValueError as e:
            raise NetworkError(str(e)) from None
        syms.add(Symbol(new_name, addr, tail.size, "func"))
        old = syms.by_name.get(fn["name"])
        if old is not None:
            old.size = head.size
        th, tt = self._make_target(proj, head, syms), self._make_target(proj, tail, syms)
        with self.store.tx() as db:
            db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=?, asm=?, seed=NULL, best_score=NULL "
                       "WHERE id=?", (head.size, len(head.lines), th.code, json.dumps(th.to_json()),
                                      self._asm_source(head), fn["id"]))
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (proj["id"], new_name, tail.size, len(tail.lines), tt.code,
                                                        json.dumps(tt.to_json()), self._asm_source(tail), None,
                                                        fn["unit"], addr, tail.rom))
            db.execute("UPDATE symbols SET size=? WHERE project_id=? AND name=?", (head.size, proj["id"], fn["name"]))
            db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                       (proj["id"], new_name, addr, tail.size, "func"))
            self._event(db, proj["id"], agent.id, "split", f"{fn['name']} / {new_name}")
        self._xrefs.pop(proj["id"], None)
        return (f"✅ split: {fn['name']} is now {len(head.lines)} instructions; {new_name} at 0x{addr:08X} has "
                f"{len(tail.lines)}. Continue with {fn['name']} (get_function shows its new assembly).")

    def _split_gba(self, agent: Agent, proj, fn, addr: int, new_name: str, syms: SymbolTable) -> str:
        """Cut a GBA function's bytes and assembly in two at `addr` (Thumb: a halfword boundary)."""
        off = addr - fn["vram"]
        if off >= fn["size"] and off % 2 == 0:  # code after the function that nobody found yet: make it a function
            return self._add_gba_function(agent, proj, fn, addr, new_name, syms)
        if off <= 0 or off >= fn["size"] or off % 2:
            raise NetworkError(f"0x{addr:08X} isn't inside {fn['name']} (0x{fn['vram']:08X}, {fn['size']} bytes)")
        head, tail = fn["target"][:off], fn["target"][off:]
        cut = re.search(rf"^(?:_|\.L){addr:08X}:|^\t(?:thumb|arm)_func_start \w*{addr:08X}\b", fn["asm"], re.M)
        asm_head, asm_tail = ((fn["asm"][:cut.start()], fn["asm"][cut.start():]) if cut else
                              (fn["asm"], f"\tthumb_func_start {new_name}\n@ split from {fn['name']}: see its assembly\n"))
        refs = json.loads(fn["relocs"])
        refs_head = [r for r in refs if r[0] < off]
        refs_tail = [[r[0] - off, r[1], r[2]] for r in refs if r[0] >= off]
        syms.add(Symbol(new_name, addr, len(tail), "func"))
        with self.store.tx() as db:
            db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=?, asm=?, seed=NULL, best_score=NULL "
                       "WHERE id=?", (len(head), max(1, len(head) // 2), head, json.dumps(refs_head), asm_head, fn["id"]))
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (proj["id"], new_name, len(tail), max(1, len(tail) // 2), tail,
                                                        json.dumps(refs_tail), asm_tail, None, fn["unit"], addr,
                                                        fn["rom_offset"] + off))
            db.execute("UPDATE symbols SET size=? WHERE project_id=? AND name=?", (len(head), proj["id"], fn["name"]))
            db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                       (proj["id"], new_name, addr, len(tail), "func"))
            self._event(db, proj["id"], agent.id, "split", f"{fn['name']} / {new_name}")
        self._xrefs.pop(proj["id"], None)
        self._ops.pop(proj["id"], None)
        return (f"✅ split: {fn['name']} is now {len(head)} bytes; {new_name} at 0x{addr:08X} has {len(tail)}. "
                f"Continue with {fn['name']} (get_function shows its new assembly).")

    def _add_gba_function(self, agent: Agent, proj, prev, addr: int, new_name: str, syms: SymbolTable) -> str:
        from ..rom import gba, gba_candidates

        nxt = self.store.one("SELECT vram FROM functions WHERE project_id=? AND vram>? ORDER BY vram LIMIT 1",
                             proj["id"], prev["vram"])
        rom, _ = self._rom(proj)
        off, limit = addr - gba.BASE, (nxt["vram"] - gba.BASE) if nxt else len(rom)
        if not off < limit or not gba_candidates.plausible_function(rom, off):
            raise NetworkError(f"0x{addr:08X} doesn't look like the start of a function")
        literals = gba_candidates.literal_words(rom, [addr])
        end = min(next(gba_candidates.bodies(rom, [addr], literals))[1], limit)
        while end + 4 <= limit and end in literals:
            end += 4
        code = rom[off:end]
        syms.add(Symbol(new_name, addr, len(code), "func"))
        with self.store.tx() as db:
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (proj["id"], new_name, len(code), max(1, len(code) // 2), code,
                                                        json.dumps(gba._refs(code, addr, literals, off)),
                                                        f"\tthumb_func_start {new_name}\n@ found by an agent after {prev['name']}\n",
                                                        None, prev["unit"], addr, off))
            db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                       (proj["id"], new_name, addr, len(code), "func"))
            self._event(db, proj["id"], agent.id, "split", f"{prev['name']} / {new_name}")
        self._xrefs.pop(proj["id"], None)
        self._ops.pop(proj["id"], None)
        return f"✅ new function {new_name} at 0x{addr:08X}, {len(code)} bytes."

    def rename_symbol(self, agent: Agent, project: str | None, old: str, new: str, message: str = "") -> str:
        self._rom_only(project, "rename_symbol")
        proj = self._project(project)
        if not self.is_rom(proj):
            return super().rename_symbol(agent, project, old, new, message)
        link = self._link(project)
        if link is not None:
            text = link.call("/collab/rename", agent, old=old, new=new, message=message)
            if text.startswith("✅"):
                link.sync()
            return text
        old, new = old.strip(), new.strip()
        if not (IDENT.match(old) and IDENT.match(new)):
            raise NetworkError("old and new must be C identifiers")
        syms = self.symbols(proj["id"])
        addr = syms.resolve(old)
        if addr is None:
            raise NetworkError(f"`{old}` is not a symbol of this ROM: use a name from the assembly (func_/D_...) "
                               f"or one given earlier")
        taken = syms.resolve(new)
        if taken is not None and taken != addr:
            raise NetworkError(f"`{new}` already names 0x{taken:08X}")
        word = re.compile(rf"\b{re.escape(old)}\b")
        trial = SymbolTable([Symbol(s.name, s.address, s.size, s.kind) for s in syms.by_name.values()])
        if old in trial.by_name:
            trial.rename(old, new)
        else:
            fnrow = self.store.one("SELECT size FROM functions WHERE project_id=? AND vram=?", proj["id"], addr)
            current, _ = syms.name_at(addr)
            base = syms.by_name.get(current) if current != f"D_{addr:08X}" else None
            trial.add(Symbol(new, addr, fnrow["size"] if fnrow else (base.size if base and base.address == addr else 0),
                             "func" if fnrow else (base.kind if base else "data")))
        units = self._unit_contexts(proj["id"])
        current_ctx = {u: self._context(proj["id"], u) for u in ({""} | units)}
        changed = {u: word.sub(new, c["header"]) for u, c in current_ctx.items() if word.search(c["header"])}
        matched = self.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])
        rewritten = {r["id"]: word.sub(new, r["matched_source"]) for r in matched}
        renamed_rows = [dict(r) | {"name": new if r["name"] == old else r["name"]} for r in matched]
        header_for = lambda fn: changed.get(self._effective_unit(fn, units),
                                            current_ctx[self._effective_unit(fn, units)]["header"])
        self._sym_override[proj["id"]] = trial
        try:
            broken = self.regression_test(proj, None, sources=rewritten, only=renamed_rows, header_for=header_for)
        finally:
            self._sym_override.pop(proj["id"], None)
        if broken:
            listing = "\n".join(f"- {n}: {why}" for n, why in broken[:10])
            return f"❌ REJECTED: renaming breaks {len(broken)} matched function(s).\n{listing}"
        msg = message.strip() or f"rename {old} -> {new}"
        with self.store.tx() as db:
            if db.execute("UPDATE symbols SET name=? WHERE project_id=? AND name=?", (new, proj["id"], old)).rowcount == 0:
                s = trial.by_name[new]
                db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                           (proj["id"], new, s.address, s.size, s.kind))
            db.execute("UPDATE functions SET name=? WHERE project_id=? AND (name=? OR vram=?)", (new, proj["id"], old, addr))
            if self.cfg(proj).get("platform") in X86_PLATFORMS:  # its listing was generated once, with the old label
                db.execute("UPDATE functions SET asm=replace(replace(asm, ?, ?), ?, ?) WHERE project_id=? AND vram=?",
                           (f"glabel {old}", f"glabel {new}", f"endlabel {old}", f"endlabel {new}", proj["id"], addr))
            for u, header in changed.items():
                version = self._next_version(db, proj["id"])
                db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                           "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, header, agent.id, msg, time.time(), u))
            for fid, src in rewritten.items():
                db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=?", (src, src, fid))
            for r in db.execute("SELECT id, best_source FROM functions WHERE project_id=? AND status='open' "
                                "AND best_source IS NOT NULL", (proj["id"],)).fetchall():
                db.execute("UPDATE functions SET best_source=? WHERE id=?", (word.sub(new, r["best_source"]), r["id"]))
            self._event(db, proj["id"], agent.id, "rename", f"{old} → {new}")
        self._syms.pop(proj["id"], None)
        return f"✅ 0x{addr:08X} is now `{new}` (was `{old}`); {len(rewritten)} matched sources updated, all still match."

    # ------------------------------------------------------------------ rooms (see collab.py)

    def link_project(self, slug: str, info: dict, client=None, start: bool = True):
        from .collab import Link

        proj = self._project(slug)
        cfg = self.cfg(proj)
        cfg["link"] = info
        with self.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        link = Link(self, slug, info["url"], info["room"], info["token"], info["member"], client=client)
        self.links[slug] = link
        if start:
            link.run()
        return link

    def restore_links(self) -> None:
        for p in self.store.all("SELECT slug, config FROM projects"):
            info = json.loads(p["config"]).get("link")
            if info and p["slug"] not in self.links:
                self.link_project(p["slug"], info)

    def unlink(self, slug: str) -> None:
        link = self.links.pop(slug, None)
        if link is not None:
            link.stop()
            try:
                link._req("POST", "/collab/leave", {})
            except NetworkError:
                pass
        proj = self._project(slug)
        cfg = self.cfg(proj)
        cfg.pop("link", None)
        with self.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))

    def _link(self, project: str | None):
        if not self.links:
            return None
        try:
            return self.links.get(self._project(project)["slug"])
        except NetworkError:
            return None

    def claim(self, agent: Agent, project: str | None = None, function: str | None = None, strategy: str = "easiest") -> str:
        try:
            proj = self._project(project)
        except NetworkError:
            proj = None
        if proj is not None and self.is_analysis(proj):
            fn = self.claim_row(agent, proj["slug"], function, strategy)
            if fn is None:
                return f"Nothing left to claim in {proj['slug']} — every open item is analyzed or claimed. 🎉"
            return self._analysis_brief(fn, agent, header="CLAIMED")
        if (fork := self.fork_slug(project)):
            return self.forks.claim(agent, fork, function, strategy)
        link = self._link(project)
        if link is None:
            return super().claim(agent, project, function, strategy)
        if function:
            function = self._function(function, project)["name"]
        name = link.claim(agent, function, strategy)
        if name is None:
            return "Nothing left to claim in this room — every open function is matched or someone is on it. 🎉"
        link.sync()
        fn = self.claim_row(agent, project, name, strategy)
        return self._brief(fn, agent, header="CLAIMED")

    def claim_many(self, agent: Agent, project: str | None, count: int, strategy: str = "easiest") -> str:
        """Several small functions at once (count 2-6): the next one by `strategy` and, when it's small, its
        neighbours in the same file. Most small functions match on the first try, so an agent writes them all and
        judges them in one compile_and_diff: a fraction of the turns. Big functions come alone."""
        count = max(1, min(int(count or 1), 6))
        try:
            proj = self._project(project)
        except NetworkError:
            proj = None
        if proj is not None and self.is_analysis(proj):
            return self.claim(agent, project, None, strategy)
        if count == 1 or self._link(project) is not None:
            return self.claim(agent, project, None, strategy)
        proj = self._project(project)
        held = self.store.all("SELECT f.* FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id=? "
                              "AND f.project_id=? ORDER BY f.vram, f.id", agent.id, proj["id"])
        if not held:
            text = self.claim(agent, project, None, strategy)  # the first, the usual way (with its "nothing left")
            held = self.store.all("SELECT f.* FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id=? "
                                  "AND f.project_id=?", agent.id, proj["id"])
            if not held or held[0]["n_insns"] > BATCH_INSNS:
                return text
        first = held[0]
        rows = list(held)
        if first["n_insns"] <= BATCH_INSNS and len(rows) < count:
            rows += self._batch_more(agent, proj, first, count - len(rows))
        if len(rows) == 1:
            return self.claim(agent, project, None, strategy)
        names = [r["name"] for r in rows]
        fork = self.fork_slug(project)
        head = (f"## CLAIMED {len(rows)} small functions: {', '.join(names)}\n"
                f"Write all of them, then judge them in one call: compile_and_diff(function=\"{', '.join(names)}\", "
                f"source=<all {len(rows)} definitions>). Each is judged on its own and saved as soon as it matches; "
                "then fix what's left (one at a time is fine). release_function any you can't do.")
        briefs = [self.forks.brief(r, agent, "CLAIMED") if fork else self._brief(r, agent, "CLAIMED") for r in rows]
        return "\n\n---\n\n".join([head, *briefs])

    def _batch_more(self, agent: Agent, proj, first, n: int) -> list:
        """Up to n more small open functions next to `first` (same file, nearest address), claimed for the agent."""
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            rows = db.execute(
                "SELECT f.* FROM functions f WHERE f.project_id=? AND f.status='open' AND f.boost >= 0 AND f.n_insns <= ? "
                "AND f.abandons = 0 AND f.unit=? AND f.id NOT IN (SELECT function_id FROM claims) "
                "ORDER BY ABS(COALESCE(f.vram, 0) - ?), f.id LIMIT ?",
                (proj["id"], BATCH_INSNS, first["unit"], first["vram"] or 0, n)).fetchall()
            for r in rows:
                db.execute("INSERT INTO claims VALUES(?,?,?,?)", (r["id"], agent.id, now, now + self.claim_ttl))
                self._event(db, proj["id"], agent.id, "claim", r["name"])
        return rows

    def attempt_many(self, agent: Agent, names: list[str], source: str, project: str | None = None) -> str:
        """compile_and_diff for several functions in one source: each judged on its own (a fork's, with the other
        definitions taken out, as its file gets them one by one), in order."""
        fork = self.fork_slug(project)
        out, matched = [], 0
        for name in names:
            try:
                one = self.forks.one_definition(fork, source, name, [n for n in names if n != name]) if fork else source
                res = self.attempt(agent, name, one, project)
            except NetworkError as e:
                res = {"text": f"❌ {e}", "matched": False}
            matched += bool(res.get("matched"))
            out.append(f"### {name}\n{res['text']}")
        return f"{matched} of {len(names)} matched.\n\n" + "\n\n".join(out)

    def _yield_autopilot(self, function: str | None, project: str | None) -> None:
        """The autopilot holds a function only while its draft compiles: an agent that wants it waits for that."""
        if not function:
            return
        try:
            fid = self._function(function, project)["id"]
        except NetworkError:
            return
        for _ in range(100):
            held = self.store.one("SELECT a.name FROM claims c JOIN agents a ON a.id=c.agent_id WHERE c.function_id=?", fid)
            if not held or held["name"] != "autopilot":
                return
            time.sleep(0.2)

    def attempt(self, agent: Agent, function: str, source: str, project: str | None = None) -> dict:
        self._yield_autopilot(function, project)
        if (fork := self.fork_slug(project)):
            return self.forks.attempt(agent, fork, function, source)
        link = self._link(project)
        before = self._function(function, project)["best_score"] if link else None
        res = super().attempt(agent, function, source, project)
        if link is None or res["score"] is None:
            return res
        name = self._function(function, project)["name"]
        if res["matched"]:
            verdict = link.attempt(agent, name, source)
            if not verdict.get("matched"):
                res["text"] += ("\n⚠️ The room's host could not confirm this match on their copy (score "
                                f"{verdict.get('score')}). Check that both of you use the same compiler settings.")
            else:
                res["text"] += "\nShared with the room: the host confirmed the match."
        elif before is None or res["score"] < before:
            threading.Thread(target=lambda: self._report(link, agent, name, source, res["score"]), daemon=True).start()
        return res

    @staticmethod
    def _report(link, agent, name, source, score) -> None:
        try:
            link.call("/collab/best", agent, function=name, source=source, score=score)
        except NetworkError:
            pass

    def apply_reported_best(self, slug: str, name: str, score: int, source: str, agent: Agent) -> None:
        """Host side: a room member's better attempt, as they report it (their own compile scored it)."""
        fn = self._function(name, slug)
        if fn["status"] != "open" or score <= 0 or (fn["best_score"] is not None and score >= fn["best_score"]):
            return
        self._record(fn, agent, score, source, self._context(fn["project_id"], fn["unit"])["version"], via="room")

    def release(self, agent: Agent, function: str, notes: str, project: str | None = None) -> str:
        if (fork := self.fork_slug(project)):
            return self.forks.release(agent, fork, function, notes)
        link = self._link(project)
        if link is not None:
            link.call("/collab/release", agent, function=self._function(function, project)["name"], notes=notes)
        return super().release(agent, function, notes, project)

    def edit_context(self, agent: Agent, project: str | None, old: str, new: str, message: str,
                     function: str | None = None) -> str:
        self._rom_only(project, "edit_context")
        link = self._link(project)
        if link is None:
            return super().edit_context(agent, project, old, new, message, function)
        text = link.call("/collab/context", agent, old=old, new=new, message=message, function=function)
        if text.startswith("✅"):
            link.sync()
        return text

    def add_note(self, agent: Agent, project: str | None, text: str, function: str | None = None) -> str:
        link = self._link(project)
        if link is None:
            return super().add_note(agent, project, text, function)
        name = self._function(function, project)["name"] if function else None
        return link.call("/collab/note", agent, text=text, function=name) or "Noted, and shared with the room."

    def _remote_agent(self, name: str) -> int:
        label = "@" + name
        if label in self._remote_ids:
            return self._remote_ids[label]
        row = self.store.one("SELECT id FROM agents WHERE name=?", label)
        if row is None:
            with self.store.tx() as db:
                aid = db.execute("INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin) VALUES(?,?,?,?,1,?)",
                                 (label, "room", "remote:" + secrets.token_hex(16), time.time(), "remote")).lastrowid
        else:
            aid = row["id"]
        self._remote_ids[label] = aid
        return aid

    def remote_event(self, project_id: int, kind: str, detail: str, agent_name: str, created_at: float) -> None:
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
                       (project_id, aid, kind, detail, created_at))

    def apply_remote_match(self, slug: str, vram: int, source: str, agent_name: str) -> None:
        proj = self._project(slug)
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            row = db.execute("SELECT id, status FROM functions WHERE project_id=? AND vram=?", (proj["id"], vram)).fetchone()
            if row is None or row["status"] == "matched":
                return
            db.execute("UPDATE functions SET status='matched', matched_source=?, matched_agent_id=?, matched_at=?, "
                       "best_score=0, best_source=? WHERE id=?", (source, aid, time.time(), source, row["id"]))
            db.execute("DELETE FROM claims WHERE function_id=?", (row["id"],))

    def apply_remote_match_named(self, slug: str, name: str, agent_name: str) -> None:
        """A git project's room: who matched a function (the code itself arrives with the host's commits)."""
        proj = self._project(slug)
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            row = db.execute("SELECT id, status, matched_agent_id FROM functions WHERE project_id=? AND name=?",
                             (proj["id"], name)).fetchone()
            if row is None:
                return
            if row["status"] != "matched":
                db.execute("UPDATE functions SET status='matched', matched_agent_id=?, matched_at=? WHERE id=?",
                           (aid, time.time(), row["id"]))
            elif row["matched_agent_id"] is None:
                db.execute("UPDATE functions SET matched_agent_id=? WHERE id=?", (aid, row["id"]))
            db.execute("DELETE FROM claims WHERE function_id=?", (row["id"],))

    def apply_remote_note_named(self, slug: str, function: str | None, text: str, agent_name: str, created_at: float) -> None:
        proj = self._project(slug)
        row = self.store.one("SELECT id FROM functions WHERE project_id=? AND name=?", proj["id"], function) if function else None
        fid = row["id"] if row else None
        if self.store.one("SELECT 1 FROM notes WHERE project_id=? AND text=? AND function_id IS ?", proj["id"], text, fid):
            return
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                       (proj["id"], fid, aid, text, created_at))

    def apply_remote_best(self, slug: str, vram: int, score: int, source: str) -> None:
        proj = self._project(slug)
        with self.store.tx() as db:
            db.execute("UPDATE functions SET best_score=?, best_source=? WHERE project_id=? AND vram=? AND status='open' "
                       "AND (best_score IS NULL OR best_score > ?)", (score, source, proj["id"], vram, score))

    def apply_remote_note(self, slug: str, host_id: int, vram: int | None, text: str, agent_name: str, created_at: float) -> None:
        proj = self._project(slug)
        fid = None
        if vram is not None:
            row = self.store.one("SELECT id FROM functions WHERE project_id=? AND vram=?", proj["id"], vram)
            fid = row["id"] if row else None
        if self.store.one("SELECT 1 FROM notes WHERE project_id=? AND text=? AND function_id IS ?", proj["id"], text, fid):
            return
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                       (proj["id"], fid, aid, text, created_at))

    def apply_remote_context(self, slug: str, header: str, host_version: int) -> None:
        proj = self._project(slug)
        if self._context(proj["id"])["header"] == header:
            return
        with self.store.tx() as db:
            version = self._next_version(db, proj["id"])
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, header, None, f"from the room (host v{host_version})",
                                                  time.time(), ""))

    def apply_remote_layout(self, slug: str, functions: list[dict], symbols: list[dict]) -> None:
        """Mirror the room's splits and names. The host already regression-tested them on the same ROM."""
        proj = self._project(slug)
        pid = proj["id"]
        local = {r["vram"]: r for r in self.store.all("SELECT * FROM functions WHERE project_id=?", pid)}
        for f in sorted(functions, key=lambda f: f["vram"]):
            if f["vram"] in local:
                continue
            owner = next((r for r in local.values() if r["vram"] < f["vram"] < r["vram"] + r["size"]), None)
            if owner is None or owner["status"] == "matched":
                continue
            rf = self._parse_asm(owner["name"], owner["asm"], owner["unit"])
            try:
                head, tail = split.split_function(rf, f["vram"], f["name"])
            except ValueError:
                continue
            syms = self.symbols(pid)
            syms.add(Symbol(f["name"], f["vram"], tail.size, "func"))
            th, tt = self._make_target(proj, head, syms), self._make_target(proj, tail, syms)
            with self.store.tx() as db:
                db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=?, asm=?, seed=NULL WHERE id=?",
                           (head.size, len(head.lines), th.code, json.dumps(th.to_json()), self._asm_source(head), owner["id"]))
                db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (pid, f["name"], tail.size, len(tail.lines), tt.code,
                                                            json.dumps(tt.to_json()), self._asm_source(tail), None,
                                                            owner["unit"], f["vram"], tail.rom))
                db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                           (pid, f["name"], f["vram"], tail.size, "func"))
            local = {r["vram"]: r for r in self.store.all("SELECT * FROM functions WHERE project_id=?", pid)}
        self._xrefs.pop(pid, None)
        syms = self.symbols(pid)
        for sym in symbols:
            current, off = syms.name_at(sym["address"])
            if off == 0 and current == sym["name"]:
                continue
            old = current if off == 0 else f"D_{sym['address']:08X}"
            word = re.compile(rf"\b{re.escape(old)}\b")
            with self.store.tx() as db:
                db.execute("DELETE FROM symbols WHERE project_id=? AND (name=? OR name=?)", (pid, old, sym["name"]))
                db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                           (pid, sym["name"], sym["address"], sym["size"], sym["kind"]))
                db.execute("UPDATE functions SET name=? WHERE project_id=? AND vram=?", (sym["name"], pid, sym["address"]))
                for r in db.execute("SELECT id, matched_source, best_source FROM functions WHERE project_id=? AND "
                                    "(matched_source IS NOT NULL OR best_source IS NOT NULL)", (pid,)).fetchall():
                    db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=?",
                               (word.sub(sym["name"], r["matched_source"]) if r["matched_source"] else None,
                                word.sub(sym["name"], r["best_source"]) if r["best_source"] else None, r["id"]))
            self._syms.pop(pid, None)
            syms = self.symbols(pid)

    # ------------------------------------------------------------------ export

    def export_rom(self, slug: str, log=print) -> dict:
        """Write a rebuildable source tree (the base for ports and mods) and prove it rebuilds the game."""
        if self.is_analysis(self._project(slug)):
            raise NetworkError("an analysis project has no source tree to export: its findings are notes on its work items")
        if self.fork_slug(slug):  # a fork's work is already in its source tree, committed
            return {"path": self._project(slug)["root"], "identical": None}
        from ..rom.export import export_rom
        from ..rom.export_gba import export_gba

        proj = self._project(slug)
        if self.cfg(proj).get("platform") in X86_PLATFORMS:
            from ..rom.export_pc import export_pc
            res = export_pc(self, slug, Path(proj["root"]).parent / f"{Path(proj['root']).name}-export", log=log)
            with self.store.tx() as db:
                cfg = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
                cfg["export"] = {"t": time.time(), "path": str(res["path"]), "identical": None,
                                 "matched": res.get("matched"), "functions": res.get("functions"),
                                 "kind": "pc"}
                db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
            return res
        export = export_gba if self.cfg(proj).get("platform") == "gba" else export_rom
        res = export(self, slug, Path(proj["root"]) / "source", log=log)
        with self.store.tx() as db:  # shown on the project page: what's in the tree and whether it rebuilds
            cfg = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
            cfg["export"] = {"t": time.time(), "path": str(res["path"]), "identical": res.get("identical"),
                             "matched": res.get("matched"), "functions": res.get("functions"),
                             "fallback": len(res.get("fallback") or [])}
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        return res

    # ------------------------------------------------------------------ for the GUI

    def overview(self, slug: str, *, backfill: bool = False) -> dict:
        proj = self._project(slug)
        last = self.store.one("SELECT MAX(created_at) AS t FROM events WHERE project_id=?", proj["id"])["t"]
        cfg = self.cfg(proj)
        # matches by the helper agents the app runs (their spend is what `spend` counts)
        helpers = self.store.one(
            "SELECT COUNT(*) AS n FROM functions f JOIN agents a ON a.id=f.matched_agent_id WHERE f.project_id=? "
            "AND f.status='matched' AND a.origin='local' AND a.name NOT IN ('you','autopilot')", proj["id"])["n"]
        twins = self.twins.jobs.get(proj["slug"])
        return self._overview(slug, proj, backfill) | {"last_activity": last, "autopilot": self.autopilot_status(slug),
                                             "permuter": self.permuter.status(proj["slug"]),
                                             "twins": None if twins is None else {
                                                 k: getattr(twins, k) for k in ("state", "pairs", "tried", "matched", "asm")},
                                             "helper_matches": helpers,
                                             "spend": cfg.get("spend"), "instructions": cfg.get("instructions") or "",
                                             "priority": cfg.get("priority", [])}

    def _repair_pc_toolchain(self, proj, cfg) -> None:
        """A PC project must compile for the target's architecture. Older imports and manual picks can name
        the x86-64 variant for a 32-bit target; fix that before anything compiles."""
        if cfg.get("platform") not in X86_PLATFORMS or not cfg.get("arch"):
            return
        old = cfg.get("compiler", {}).get("toolchain") or ""
        try:
            toolchains.get(old)
        except toolchains.ToolchainError:
            return
        fixed = arch_toolchain(old, cfg["arch"])
        if (cfg.get("rom") or {}).get("language_guess") == "C++" and source_language(fixed) != "C++":
            fixed = cxx_toolchain(fixed)
        if fixed == old:
            return
        cfg["compiler"]["toolchain"] = fixed
        with self.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
            self._event(db, proj["id"], None, "compiler", f"{fixed} for this {cfg['arch']} target")

    def _backfill_detection(self, proj, cfg) -> dict:
        """Old PC projects stored only a rough .comment guess; read the target once and keep the details."""
        rom = cfg["rom"]
        name = rom.get("program") or rom.get("file")
        if not name:
            return rom
        path = Path(proj["root"]) / name
        try:
            if not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
                return rom
            picked = detect.identify(path, name)
        except Exception:
            return rom
        if picked.platform not in X86_PLATFORMS:
            return rom
        try:
            from ..rom import elfexe
            image = (elfexe if picked.platform == "linux" else pe).read(picked.data, picked.filename)
        except Exception:
            return rom
        changed = False
        for key in ("language_guess", "compiler_version", "build_label", "matchable", "compiler_guess"):
            value = picked.info.get(key)
            if value is not None and rom.get(key) != value:
                rom[key] = value
                changed = True
        old_tc = cfg["compiler"]["toolchain"]
        tc_id = arch_toolchain(old_tc, image.arch)
        if picked.info.get("language_guess") == "C++" and source_language(tc_id) != "C++":
            tc_id = cxx_toolchain(tc_id)
        if tc_id != old_tc:
            cfg["compiler"]["toolchain"] = tc_id
            changed = True
        if cfg.get("arch") != image.arch:
            cfg["arch"] = image.arch
            changed = True
        want_style = "msvc" if tc_id.startswith("clang-cl") else "gnu"
        if not rom.get("suggested_flags") or rom.get("flag_style") != want_style:
            try:
                tc = toolchains.get(tc_id)
                base = cfg["compiler"].get("flags") or tc.flags
                suggestion = buildinfo.infer_flags(
                    picked.data, compiler="MSVC" if want_style == "msvc" else "GNU",
                    cxx=picked.info.get("language_guess") == "C++", base_flags=base, symbols=image.symbols,
                    section_names=[s.name for s in image.sections])
                rom["suggested_flags"], rom["flag_evidence"] = suggestion["flags"], suggestion["evidence"]
                rom["flag_style"] = suggestion["style"]
                changed = True
            except Exception:
                pass
        if changed:
            cfg["rom"] = rom
            with self.store.tx() as db:
                db.execute("UPDATE projects SET config=?, arch=? WHERE id=?",
                           (json.dumps(cfg), cfg.get("arch") or proj["arch"], proj["id"]))
        self.classify_library(proj["slug"], log=lambda *_: None)
        return rom

    def _overview(self, slug: str, proj, backfill: bool = False) -> dict:
        if (fork := self.fork_slug(slug)):
            return self.forks.overview(fork)
        if self.is_analysis(proj):
            return self._analysis_overview(proj)
        cfg = self.cfg(proj)
        if cfg.get("platform") in X86_PLATFORMS:
            self._repair_pc_toolchain(proj, cfg)
        agg = self.store.one(
            "SELECT COUNT(*) AS total, SUM(status='matched') AS matched, SUM(size) AS bytes, "
            "SUM(CASE WHEN status='matched' THEN size ELSE 0 END) AS matched_bytes, SUM(attempts) AS attempts, "
            "SUM(hits>0) AS traced, SUM(hits) AS hits "
            "FROM functions WHERE project_id=? AND status!='library'", proj["id"])
        lib = self.store.one("SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND status='library'",
                             proj["id"])["n"]
        rom = cfg["rom"]
        detected = None
        if cfg.get("platform") in X86_PLATFORMS:
            want_style = "msvc" if cfg["compiler"]["toolchain"].startswith("clang-cl") else "gnu"
            try:
                tool_arch = toolchains.get(cfg["compiler"]["toolchain"]).arch
            except toolchains.ToolchainError:
                tool_arch = ""
            wrong_arch = bool(tool_arch and cfg.get("arch") and tool_arch != cfg["arch"])
            if backfill and (not rom.get("build_label") or not rom.get("suggested_flags") or
                             rom.get("flag_style") != want_style or wrong_arch or (
                    rom.get("language_guess") == "C++" and source_language(cfg["compiler"]["toolchain"]) != "C++")):
                rom = self._backfill_detection(proj, cfg)
            language = rom.get("language_guess") or source_language(cfg["compiler"]["toolchain"])
            guess = rom.get("compiler_guess") or ""
            label = rom.get("build_label") or buildinfo.label_from_guess(guess, language)
            detected = {"language": language, "compiler": guess, "version": rom.get("compiler_version") or "",
                        "label": label, "matchable": rom.get("matchable", True)}
        tc = toolchains.get(cfg["compiler"]["toolchain"])
        return {
            "slug": proj["slug"], "title": proj["name"], "description": proj["description"],
            "platform": cfg.get("platform", "n64"), "platform_name": detect.PLATFORMS.get(cfg.get("platform", "n64"), ""),
            "compilers": PLATFORM_COMPILERS.get(cfg.get("platform", "n64"), []),
            "rom": {k: rom.get(k) for k in ("title", "game_code", "region", "size", "sha1", "byte_order", "compiler_guess")},
            "detected": (detected or {}) | ({"suggested_flags": rom.get("suggested_flags") or [],
                                            "flag_evidence": rom.get("flag_evidence") or []} if detected else {}),
            "compiler": {"toolchain": tc.id, "name": SHORT_NAMES.get(tc.id, tc.name), "flags": cfg["compiler"]["flags"],
                         "installed": toolchains.installed(tc.id) is not None, "proprietary": tc.proprietary,
                         "supported": tc.supported, "system": tc.system, "wsl": tc.via_wsl,
                         "command": tc.cmd[0] if tc.cmd else "",
                         "download": tc.download if toolchains.current_platform().startswith("windows") else "",
                         "why": None if tc.supported else toolchains.unsupported_cpu()},
            "source_language": source_language(tc.id), "source_ext": source_ext(tc.id),
            "functions": agg["total"] or 0, "matched": agg["matched"] or 0, "bytes": agg["bytes"] or 0,
            "matched_bytes": agg["matched_bytes"] or 0, "attempts": agg["attempts"] or 0, "library": lib,
            "traced": agg["traced"] or 0, "hits": agg["hits"] or 0,
            "data": self.store.one("SELECT COUNT(*) AS n FROM symbols WHERE project_id=? AND kind!='func'",
                                    proj["id"])["n"],
            "context_version": self._context(proj["id"])["version"],
            "folder": proj["root"],
            "export": cfg.get("export"),
            "exportable": cfg.get("platform", "n64") in ("n64", "psx", "ps2", "gba", *X86_PLATFORMS),
            "debug": cfg.get("debug"),
            "binary": cfg.get("rom", {}).get("program") if cfg.get("platform") in X86_PLATFORMS else None,
            "room": self._room_info(proj["slug"]),
        }

    def _analysis_overview(self, proj) -> dict:
        cfg = self.cfg(proj)
        target = cfg.get("target") or {}
        agg = self.store.one(
            "SELECT COUNT(*) AS total, SUM(status='matched') AS matched, SUM(size) AS bytes, "
            "SUM(CASE WHEN status='matched' THEN size ELSE 0 END) AS matched_bytes, "
            "SUM(attempts) AS attempts, SUM(abandons) AS releases FROM functions WHERE project_id=?", proj["id"])
        notes = self.store.one("SELECT COUNT(*) AS n FROM notes WHERE project_id=?", proj["id"])["n"]
        fmt = target.get("format") or "target"
        arch = target.get("architecture") or "unknown"
        return {
            "slug": proj["slug"], "title": proj["name"], "description": proj["description"],
            "kind": "analysis", "platform": "rea",
            "platform_name": (fmt.upper() if fmt and fmt != "target" else "Binary"),
            "compilers": [],
            "rom": {"title": proj["name"], "game_code": "", "region": "", "size": target.get("size"),
                    "sha1": target.get("sha256"), "byte_order": "", "compiler_guess": fmt},
            "compiler": {"toolchain": "rea", "name": "REA", "flags": [], "installed": True,
                         "proprietary": False, "supported": True, "wsl": False, "why": None},
            "analysis": {"target": target, "counts": cfg.get("counts") or {}, "segments": cfg.get("segments") or [],
                         "provider": cfg.get("provider") or "", "notes": notes,
                         "artifact": cfg.get("artifact") or {}, "children": cfg.get("children") or []},
            "entries": (cfg.get("artifact") or {}).get("entries"),
            "files": (cfg.get("artifact") or {}).get("files"),
            "source": cfg.get("source") or None,
            "functions": agg["total"] or 0, "matched": agg["matched"] or 0, "bytes": agg["bytes"] or 0,
            "matched_bytes": agg["matched_bytes"] or 0, "attempts": agg["attempts"] or 0,
            "releases": agg["releases"] or 0, "findings": notes,
            "context_version": 1,
            "folder": proj["root"],
            "export": None, "exportable": False,
            "binary": target.get("path"),
            "room": self._room_info(proj["slug"]),
        }

    def _room_info(self, slug: str) -> dict | None:
        if slug in self.links:
            link = self.links[slug]
            return {"role": "guest", "host": link.url, "member": link.member, "error": link.error,
                    "members": link.members, "connected": time.time() - link.last_ok < 15}
        if slug in self.rooms:
            return {"role": "host", "members": self.rooms[slug].members()}
        return None

    def import_trace(self, slug: str, path: str, log=print) -> dict:
        """Fold a debugger/emulator coverage file into the project: every hit becomes a function's hit count."""
        proj = self._project(slug)
        trace = tracefile.read(path)
        cfg = self.cfg(proj)
        image_base = int(cfg.get("rom", {}).get("image_base") or 0)
        rows = self.store.all("SELECT id, name, vram, size FROM functions WHERE project_id=? AND vram IS NOT NULL",
                              proj["id"])
        by_name = {r["name"]: r for r in rows}
        by_addr = {int(r["vram"]): r for r in rows}
        starts = sorted(by_addr)
        import bisect
        def find(addr: int):
            if addr in by_addr:
                return by_addr[addr]
            i = bisect.bisect_right(starts, addr) - 1
            if i >= 0:
                r = by_addr[starts[i]]
                if addr < int(r["vram"]) + int(r["size"] or 0):
                    return r
            return None
        hits: dict[int, int] = {}
        unmatched = 0
        for hit in trace.hits:
            row = by_name.get(hit.name) if hit.name else None
            if row is None and hit.address is not None:
                candidates = [hit.address]
                if image_base:
                    if hit.address < image_base:
                        candidates.append(hit.address + image_base)
                    else:
                        candidates.append(hit.address - image_base)
                for addr in candidates:
                    row = find(addr)
                    if row is not None:
                        break
            if row is None:
                unmatched += 1
                continue
            hits[row["id"]] = hits.get(row["id"], 0) + hit.count
        now = time.time()
        if hits:
            with self.store.tx() as db:
                db.executemany("UPDATE functions SET hits=hits+?, trace_at=? WHERE id=?",
                               [(n, now, fid) for fid, n in hits.items()])
                db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
                           (proj["id"], None, "trace", f"{sum(hits.values())} hits in {len(hits)} functions from {trace.source}",
                            now))
        top = sorted(((self.store.one("SELECT name, vram, hits FROM functions WHERE id=?", fid), n) for fid, n in hits.items()),
                     key=lambda x: -x[1])[:10]
        log(f"trace {trace.source}: {sum(hits.values())} hits in {len(hits)} functions, {unmatched} unmatched")
        return {"source": trace.source, "hits": sum(hits.values()), "functions": len(hits), "unmatched": unmatched,
                "skipped": trace.skipped,
                "top": [{"name": r["name"], "vram": int(r["vram"]), "hits": n} for r, n in top]}

    def hot_functions(self, slug: str, limit: int = 40) -> list[dict]:
        proj = self._project(slug)
        rows = self.store.all(
            "SELECT name, vram, size, hits, trace_at FROM functions WHERE project_id=? AND hits>0 "
            "ORDER BY hits DESC, name LIMIT ?", proj["id"], max(1, min(int(limit), 500)))
        return [{"name": r["name"], "vram": int(r["vram"] or 0), "size": int(r["size"] or 0),
                 "hits": int(r["hits"] or 0), "trace_at": r["trace_at"]} for r in rows]

    def data_symbols(self, slug: str, query: str = "", limit: int = 500) -> list[dict]:
        """Data and string symbols the target already names, as a readable inventory (not code work items)."""
        proj = self._project(slug)
        rows = self.store.all(
            "SELECT name, address, size, kind, preview FROM symbols WHERE project_id=? AND kind!='func' "
            "ORDER BY address, name", proj["id"])
        q = query.strip().lower()
        out = []
        for i, r in enumerate(rows):
            if q and q not in (r["name"] or "").lower() and q not in (r["preview"] or "").lower():
                continue
            size = int(r["size"] or 0)
            if not size and i + 1 < len(rows):
                size = max(0, int(rows[i + 1]["address"] or 0) - int(r["address"] or 0))
            out.append({"name": r["name"], "address": int(r["address"] or 0), "size": size,
                        "kind": r["kind"] or "data", "preview": r["preview"] or ""})
            if len(out) >= max(1, min(int(limit), 5000)):
                break
        return out

    def function_map(self, slug: str) -> list[dict]:
        proj = self._project(slug)
        rows = self.store.all(
            "SELECT f.name, f.vram, f.size, f.n_insns, f.status, f.meta, f.best_score, f.attempts, f.hits, f.unit, f.matched_at, "
            "a.name AS agent, m.name AS matched_by FROM functions f LEFT JOIN claims c ON c.function_id=f.id "
            "LEFT JOIN agents a ON a.id=c.agent_id LEFT JOIN agents m ON m.id=f.matched_agent_id "
            "WHERE f.project_id=? ORDER BY f.vram, f.unit, f.id", proj["id"])
        link = self.links.get(slug)
        # who works on what in the room: by address, or by name in a git project (its functions have no addresses)
        key = (lambda r: r["name"]) if link is not None and link.fork else (lambda r: r["vram"])
        remote = {key(c): "@" + c["agent"] for c in (link.claims if link is not None else [])}
        out = []
        for r in rows:
            meta = json.loads(r["meta"] or "{}")
            status = "library" if r["status"] == "library" else (
                r["status"] if r["status"] in ("matched", "asm") else
                "working" if (r["agent"] or key(r) in remote) else "open")
            out.append({"name": r["name"], "vram": r["vram"], "size": r["size"], "insns": r["n_insns"],
                        "unit": r["unit"], "kind": meta.get("kind") or "", "status": status,
                        "library": meta.get("library"),
                        "best": r["best_score"], "attempts": r["attempts"], "hits": int(r["hits"] or 0),
                        "agent": r["agent"] or remote.get(key(r)), "matched_at": r["matched_at"],
                        "matched_by": r["matched_by"]})
        return out

    def map_signature(self, slug: str) -> str:
        """What the function map shows, summed up: it changes when a function is added, matched, tried or claimed.
        A few sums over indexed rows, so the GUI can ask "anything new?" every few seconds without fetching tens of
        thousands of functions (renames and splits come with events, which refetch anyway)."""
        proj = self._project(slug)
        f = self.store.one("SELECT COUNT(*) AS n, COALESCE(MAX(id), 0) AS hi, COALESCE(SUM(attempts), 0) AS at, "
                           "COALESCE(SUM(status='matched'), 0) AS m, COALESCE(SUM(best_score), 0) AS bs, "
                           "COALESCE(MAX(matched_at), 0) AS ma FROM functions WHERE project_id=?", proj["id"])
        c = self.store.one("SELECT COUNT(*) AS n, COALESCE(SUM(c.function_id * 31 + c.agent_id), 0) AS k FROM claims c "
                           "JOIN functions f ON f.id=c.function_id WHERE f.project_id=?", proj["id"])
        link = self.links.get(slug)
        remote = sorted(str(x.get("vram") or x.get("name")) + x.get("agent", "") for x in (link.claims if link else []))
        return f"{f['n']}.{f['hi']}.{f['at']}.{f['m']}.{f['bs']}.{f['ma']}.{c['n']}.{c['k']}.{hash(tuple(remote)) & 0xFFFFFF}"

    # ------------------------------------------------------------------ what agents spend, and steering them

    def _update_cfg(self, slug: str, change) -> dict:
        """Change a project's config in one transaction (change(cfg) edits it in place)."""
        proj = self._project(slug)
        with self.store.tx() as db:
            cfg = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
            change(cfg)
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        return cfg

    def add_spend(self, slug: str, usd: float, tokens: int) -> None:
        if usd or tokens:
            def change(cfg):
                sp = cfg.setdefault("spend", {"usd": 0.0, "tokens": 0})
                sp["usd"] = round(sp.get("usd", 0) + usd, 6)
                sp["tokens"] = sp.get("tokens", 0) + tokens
            self._update_cfg(slug, change)

    def spend(self, slug: str) -> dict | None:
        return self.cfg(self._project(slug)).get("spend")

    def set_instructions(self, slug: str, text: str) -> None:
        """What the user wants agents to know or focus on, given to every agent on this project."""
        self._update_cfg(slug, lambda cfg: cfg.__setitem__("instructions", text.strip()[:4000]))

    def instructions(self, slug: str) -> str:
        return self.cfg(self._project(slug)).get("instructions") or ""

    def references(self, slug: str) -> list[Path]:
        """Folders named in the user's instructions that the project's agents may read (ROM projects; not in a
        room, whose instructions could come from someone else's computer)."""
        from . import references

        if self.fork_slug(slug) or self.links.get(slug) is not None:
            return []
        return references.named(self.instructions(slug))

    def set_priority(self, slug: str, name: str, on: bool = True) -> list[str]:
        """Functions the user wants done next: automatic claims take these first."""
        fn = self._function(name, slug)

        def change(cfg):
            items = [n for n in cfg.get("priority", []) if n != fn["name"]]
            cfg["priority"] = ([fn["name"]] + items) if on else items
        return self._update_cfg(slug, change)["priority"]

    def claim_row(self, agent: Agent, project: str | None = None, function: str | None = None, strategy: str = "easiest"):
        if function is None and project and not self.fork_slug(project):
            proj = self._project(project)
            for name in self.cfg(proj).get("priority", []):
                row = self.store.one("SELECT f.id, f.status FROM functions f WHERE f.project_id=? AND f.name=?", proj["id"], name)
                held = self.store.one("SELECT 1 FROM claims WHERE agent_id=?", agent.id)
                if row and row["status"] == "open" and not held and not self.store.one(
                        "SELECT 1 FROM claims WHERE function_id=?", row["id"]):
                    function = name
                    break
        self._yield_autopilot(function, project)
        return Network.claim_row(self, agent, project, function, strategy)

    # ------------------------------------------------------------------ autopilot

    def start_autopilot(self, slug: str, workers: int = 3) -> dict:
        """Try every open function's machine draft (m2c, compilable form) through the judge, smallest first, in the
        background. Whatever already matches is saved before any agent spends a token on it; drafts that compile
        become the function's best attempt, so agents start from them. Agents and autopilot never collide: a
        function is held only while its draft compiles, and claimed ones are skipped."""
        state = self.autopilots.get(slug)
        if state and state["state"] == "running":
            return state
        if self.is_analysis(self._project(slug)):
            raise NetworkError("autopilot is for matching projects: an analysis project's agents read the target with REA")
        # first the twins (identical code to something matched: every project), then machine drafts where m2c reads
        # the code and the project's headers are fit for them (ROM projects; games started from scratch)
        try:
            if (fork := self.fork_slug(slug)):  # a GameCube, Wii or DS game started from scratch: its own build judges
                ids = self.forks.autopilot_prepare(fork)
                try_one, workers = self.forks.autopilot_one, min(workers, 2)  # each try builds a file: fewer at once
            else:
                if not seeds.available():
                    raise NetworkError("autopilot's drafts need m2c, the draft decompiler: install it in Setup")
                proj = self._project(slug)
                tc = self.cfg(proj)["compiler"]["toolchain"]
                if not seeds.M2C_TARGETS.get(tc):
                    raise NetworkError("m2c can't read this project's code (no draft decompiler for it yet)")
                ids = [r["id"] for r in self.store.all("SELECT id FROM functions WHERE project_id=? AND status='open' "
                                                       "ORDER BY n_insns, vram", proj["id"])]
                try_one = self._autopilot_one
            no_drafts = ""
        except NetworkError as e:
            ids, try_one, no_drafts = [], None, str(e)
        state = {"state": "running", "total": len(ids), "tried": 0, "matched": 0, "near": 0, "twins": 0,
                 "phase": "twins", "no_drafts": no_drafts, "started_at": time.time(), "stop": threading.Event()}
        self.autopilots[slug] = state
        threading.Thread(target=self._autopilot_run, args=(slug, ids, state, workers, try_one),
                         daemon=True, name=f"autopilot-{slug}").start()
        return state

    def stop_autopilot(self, slug: str) -> None:
        if (state := self.autopilots.get(slug)) and state["state"] == "running":
            state["stop"].set()

    def autopilot_status(self, slug: str) -> dict | None:
        state = self.autopilots.get(slug)
        if state:
            return {k: v for k, v in state.items() if k != "stop"}
        last = self.cfg(self._project(slug)).get("autopilot")  # the last run, from before the app restarted
        return {"state": "done", **last} if last else None

    def _autopilot_run(self, slug: str, ids: list[int], state: dict, workers: int, try_one=None) -> None:
        from concurrent.futures import ThreadPoolExecutor

        agent, _ = self.local_agent("autopilot")
        proj = self._project(slug)
        try_one = try_one or self._autopilot_one
        try:  # identical code first: free, and it takes those functions off the drafts' list
            if slug not in self.links:  # (a room member's matches come from the host)
                job = self.twins.full_pass(slug)
                state["twins"] = job.matched
                state["matched"] += job.matched
        except Exception as e:
            logging.getLogger("decomp.wtf").info("autopilot twins: %s", e)
        state["phase"] = "drafts"
        ids = [fid for fid in ids if (r := self.store.one("SELECT status FROM functions WHERE id=?", fid)) and r["status"] == "open"]
        state["total"] = len(ids)

        def one(fid: int) -> None:
            if state["stop"].is_set():
                return
            try:
                outcome = try_one(agent, proj, fid)
            except Exception:  # one odd function must not stop the rest
                outcome = "fail"
            state["tried"] += 1
            if outcome in ("match", "near"):
                state[{"match": "matched", "near": "near"}[outcome]] += 1

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(one, ids))
        finally:
            state["state"] = "stopped" if state["stop"].is_set() else "done"
            state["finished_at"] = time.time()
            with self.store.tx() as db:
                cfg = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
                cfg["autopilot"] = {k: state.get(k) for k in ("total", "tried", "matched", "near", "twins", "started_at",
                                                              "finished_at")}
                db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
            drafts = state["matched"] - state.get("twins", 0)
            if drafts:  # (twins announce their own)
                with self.store.tx() as db:
                    self._event(db, proj["id"], agent.id, "autopilot",
                                f"{drafts} of {state['tried']} functions matched from machine drafts")

    def on_match(self, proj, function_id: int, agent: Agent | None = None) -> None:
        """Its twins get its code, at once. (Not for the full twins pass's own matches while it runs: it tries
        those twins itself.)"""
        if proj is None:
            return
        if agent is not None and agent.name == "autopilot" and self.twins._full_running(proj["slug"]):
            return
        self.twins.after_match(proj, function_id)

    def try_quietly(self, agent, proj, fn, source: str) -> dict:
        """Judge one candidate for a function nobody holds (autopilot's tries): held only while it compiles,
        recorded as an attempt like any other. {"matched", "score"}."""
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            if db.execute("SELECT 1 FROM claims WHERE function_id=?", (fn["id"],)).fetchone():
                raise NetworkError(f"{fn['name']} is claimed")
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + 300))
        try:
            ctx = self._context(proj["id"], fn["unit"])
            result = self._compile(proj, ctx["header"], source)
            if not result.ok:
                return {"matched": False, "score": None}
            cand, verdict, _ = self._evaluate(fn, proj, result.obj)
            if cand is None:
                return {"matched": False, "score": None}
            d = scoring.diff(self._target_obj(fn, proj), cand)
            if verdict is not None:
                d = scoring.DiffResult(0 if verdict else max(1, d.score), d.max_score, d.rows, verdict)
            self._record(fn, agent, d.score, source, ctx["version"], matched=d.bytes_match)
            return {"matched": d.bytes_match, "score": d.score}
        finally:
            with self.store.tx() as db:
                db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fn["id"], agent.id))

    def _autopilot_one(self, agent, proj, fid: int) -> str:
        """match | near | far | fail | skip, for one function's draft."""
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            fn = db.execute("SELECT * FROM functions WHERE id=?", (fid,)).fetchone()
            if fn is None or fn["status"] != "open" or db.execute("SELECT 1 FROM claims WHERE function_id=?", (fid,)).fetchone():
                return "skip"
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fid, agent.id, now, now + 300))
        if self.cfg(proj).get("platform") in X86_PLATFORMS:
            return "skip"  # m2c has no x86 target; a draft comes from REA (inspect_binary) instead
        try:
            self._seed_for(fn, proj)  # the readable draft, for the agents that come after
            ctx = self._context(proj["id"], fn["unit"])
            data_asm = "\n".join(self._jtbl_asm(proj, fn)) if "jtbl_" in (fn["asm"] or "") else None
            draft = seeds.generate_from_asm(self._asm_text(fn, proj), fn["name"], self.cfg(proj)["compiler"]["toolchain"],
                                            ctx["header"], data_asm, valid=True)
            if not draft:
                return "fail"
            source = f"/* machine draft (m2c), tried by autopilot */\n{seeds.M2C_MACROS}\n{draft}\n"
            result = self._compile(proj, ctx["header"], source)
            if not result.ok:
                return "fail"
            cand, verdict, _ = self._evaluate(fn, proj, result.obj)
            if cand is None:
                return "fail"
            d = scoring.diff(self._target_obj(fn, proj), cand)
            if verdict is not None:
                d = scoring.DiffResult(0 if verdict else max(1, d.score), d.max_score, d.rows, verdict)
            self._record(fn, agent, d.score, source, ctx["version"], matched=d.bytes_match)
            return "match" if d.bytes_match else "near" if d.percent >= 90 else "far"
        finally:
            with self.store.tx() as db:
                db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fid, agent.id))

    def function_diff(self, slug: str, name: str, which: str = "latest") -> dict:
        """The target next to an attempt, instruction by instruction, for the GUI: the matched C, else the latest
        (or best) attempt, compiled and linked like the judge does. Cached, so watching an agent costs nothing."""
        if (fork := self.fork_slug(slug)):
            return self.forks.function_diff(fork, name)
        fn = self._function(name, slug)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        latest = self.store.one("SELECT source FROM attempts WHERE function_id=? AND source IS NOT NULL "
                                "ORDER BY id DESC LIMIT 1", fn["id"])
        picks = [("matched", fn["matched_source"]), ("best", fn["best_source"]),
                 ("latest", latest["source"] if latest else None)]
        if which == "latest":
            picks = [picks[0], picks[2], picks[1]]
        kind, source = next(((k, v) for k, v in picks if v), (None, None))
        if source is None:
            return {"kind": None, "rows": None}
        ctx = self._context(proj["id"], fn["unit"])
        key = (fn["id"], hashlib.sha1(source.encode()).hexdigest(), ctx["version"], proj["config"])
        if key in self._diffs:
            return self._diffs[key] | {"kind": kind}
        result = self._compile(proj, ctx["header"], source)
        if not result.ok:
            out = {"rows": None, "error": result.log.strip()[-3000:] or "it didn't compile", "source": source}
        else:
            cand, verdict, problems = self._evaluate(fn, proj, result.obj)
            if cand is None:
                out = {"rows": None, "error": f"the object has no function named `{fn['name']}`", "source": source}
            else:
                d = scoring.diff(self._target_obj(fn, proj), cand)
                if verdict is not None:
                    d = scoring.DiffResult(0 if verdict else max(1, d.score), d.max_score, d.rows, verdict)
                out = {"rows": [list(r) for r in d.rows], "score": d.score,
                       "percent": 100.0 if d.bytes_match else min(99.9, int(d.percent * 10) / 10),
                       "problems": problems, "source": source}
        if len(self._diffs) > 128:
            self._diffs.pop(next(iter(self._diffs)))
        self._diffs[key] = out
        return out | {"kind": kind}

    def function_detail(self, slug: str, name: str) -> dict:
        if (fork := self.fork_slug(slug)):
            return self.forks.function_detail(fork, name)
        fn = self._function(name, slug)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        if self.is_analysis(proj):
            notes = self.store.all("SELECT n.text, n.created_at, a.name AS agent FROM notes n LEFT JOIN agents a "
                                   "ON a.id=n.agent_id WHERE n.function_id=? ORDER BY n.id DESC LIMIT 10", fn["id"])
            meta = json.loads(fn["meta"] or "{}")
            return {"name": fn["name"], "vram": fn["vram"], "rom_offset": 0, "size": fn["size"],
                    "insns": 0, "status": fn["status"], "best": fn["best_score"], "asm": "",
                    "source": fn["matched_source"] or fn["best_source"], "source_kind": "analysis" if fn["matched_source"] else None,
                    "scores": [], "notes": [dict(n) for n in notes], "calls": [], "called_by": [],
                    "kind": meta.get("kind") or "procedure", "address": meta.get("address") or 0}
        attempts = self.store.all(
            "SELECT t.score, t.created_at, a.name AS agent FROM attempts t LEFT JOIN agents a ON a.id=t.agent_id "
            "WHERE t.function_id=? ORDER BY t.id", fn["id"])
        latest = self.store.one("SELECT source, score FROM attempts WHERE function_id=? AND source IS NOT NULL "
                                "ORDER BY id DESC LIMIT 1", fn["id"])
        notes = self.store.all("SELECT n.text, n.created_at, a.name AS agent FROM notes n LEFT JOIN agents a "
                               "ON a.id=n.agent_id WHERE n.function_id=? ORDER BY n.id DESC LIMIT 10", fn["id"])
        x = self.xrefs(proj)
        syms = self.symbols(proj["id"])
        if not (fn["matched_source"] or fn["best_source"] or latest) and fn["seed"] is None:
            with self._seed_lock:
                self._seed_for(fn, proj)
            fn = self._function(fn["name"], slug)
        return {
            "name": fn["name"], "vram": fn["vram"], "rom_offset": fn["rom_offset"], "size": fn["size"],
            "insns": fn["n_insns"], "status": fn["status"], "best": fn["best_score"],
            "asm": self._asm_text(fn, proj),
            "source": fn["matched_source"] or fn["best_source"] or (latest["source"] if latest else None) or fn["seed"],
            "source_kind": "matched" if fn["matched_source"] else "best" if fn["best_source"] else
                           "latest" if latest else "draft" if fn["seed"] else None,
            "scores": [{"score": a["score"], "t": a["created_at"], "agent": a["agent"]} for a in attempts],
            "notes": [dict(n) for n in notes],
            "calls": [syms.label(a) for a in sorted(x["calls"].get(fn["vram"], ()))],
            "called_by": [syms.label(a) for a in sorted(x["called_by"].get(fn["vram"], ()))],
        }

    def stats(self, slug: str) -> dict:
        """Who did what and how fast: the overview's numbers (asked every few seconds, not every second)."""
        proj = self._project(slug)
        pid = proj["id"]
        now = time.time()
        if self.is_analysis(proj):
            rows = self.store.all(
                "SELECT a.name AS agent, COUNT(n.id) AS compiles, MAX(n.created_at) AS last FROM notes n "
                "JOIN agents a ON a.id=n.agent_id WHERE n.project_id=? GROUP BY a.id", pid)
            matched = {r["agent"]: r["n"] for r in self.store.all(
                "SELECT a.name AS agent, COUNT(*) AS n FROM functions f JOIN agents a ON a.id=f.matched_agent_id "
                "WHERE f.project_id=? AND f.status='matched' GROUP BY a.id", pid)}
            board = [{"agent": r["agent"], "compiles": r["compiles"], "matched": matched.pop(r["agent"], 0), "last": r["last"]}
                     for r in rows]
            board += [{"agent": a, "compiles": 0, "matched": n, "last": None} for a, n in matched.items()]
            board.sort(key=lambda r: (-r["matched"], -r["compiles"]))
            per_hour = [0] * 24
            for r in self.store.all("SELECT matched_at FROM functions WHERE project_id=? AND status='matched' "
                                    "AND matched_at > ?", pid, now - 86400):
                per_hour[23 - min(23, max(0, int((now - r["matched_at"]) // 3600)))] += 1
            notes = self.store.one("SELECT COUNT(*) AS n FROM notes WHERE project_id=? AND created_at > ?",
                                   pid, now - 3600)["n"]
            return {"agents": board[:24], "matches_per_hour": per_hour, "compiles_last_hour": notes}
        rows = self.store.all(
            "SELECT a.name AS agent, COUNT(t.id) AS compiles, MAX(t.created_at) AS last FROM attempts t "
            "JOIN functions f ON f.id=t.function_id JOIN agents a ON a.id=t.agent_id WHERE f.project_id=? GROUP BY a.id", pid)
        matched = {r["agent"]: r["n"] for r in self.store.all(
            "SELECT a.name AS agent, COUNT(*) AS n FROM functions f JOIN agents a ON a.id=f.matched_agent_id "
            "WHERE f.project_id=? AND f.status='matched' GROUP BY a.id", pid)}
        board = [{"agent": r["agent"], "compiles": r["compiles"], "matched": matched.pop(r["agent"], 0), "last": r["last"]}
                 for r in rows]
        board += [{"agent": a, "compiles": 0, "matched": n, "last": None} for a, n in matched.items()]
        board.sort(key=lambda r: (-r["matched"], -r["compiles"]))
        per_hour = [0] * 24
        for r in self.store.all("SELECT matched_at FROM functions WHERE project_id=? AND status='matched' AND matched_at > ?",
                                pid, now - 86400):
            per_hour[23 - min(23, max(0, int((now - r["matched_at"]) // 3600)))] += 1  # (one matched since `now`: this hour)
        compiles = self.store.one("SELECT COUNT(*) AS n FROM attempts t JOIN functions f ON f.id=t.function_id "
                                  "WHERE f.project_id=? AND t.created_at > ?", pid, now - 3600)["n"]
        return {"agents": board[:24], "matches_per_hour": per_hour, "compiles_last_hour": compiles}

    def live(self, slug: str, since_event: int = 0, since_attempt: int = 0) -> dict:
        proj = self._project(slug)
        with self.store.tx() as db:
            self._expire_claims(db)
        events = self.store.all(
            "SELECT e.id, e.kind, e.detail, e.created_at, a.name AS agent FROM events e LEFT JOIN agents a "
            "ON a.id=e.agent_id WHERE e.project_id=? AND e.id>? ORDER BY e.id DESC LIMIT 60", proj["id"], since_event)
        attempts = self.store.all(
            "SELECT t.id, t.score, t.compiled, t.created_at, f.name AS function, f.n_insns, a.name AS agent "
            "FROM attempts t JOIN functions f ON f.id=t.function_id LEFT JOIN agents a ON a.id=t.agent_id "
            "WHERE f.project_id=? AND t.id>? ORDER BY t.id DESC LIMIT 80", proj["id"], since_attempt)
        claims = self.store.all(
            "SELECT f.name, f.n_insns, f.best_score, f.attempts, a.name AS agent, c.claimed_at FROM claims c "
            "JOIN functions f ON f.id=c.function_id JOIN agents a ON a.id=c.agent_id WHERE f.project_id=?", proj["id"])
        claims = [dict(c) for c in claims]
        if slug in self.links:
            for c in self.links[slug].claims:
                row = self.store.one("SELECT name, n_insns, best_score, attempts FROM functions WHERE project_id=? AND vram=?",
                                     proj["id"], c["vram"])
                if row:
                    claims.append(dict(row) | {"agent": "@" + c["agent"], "claimed_at": None})
        return {"events": [dict(e) for e in reversed(events)], "attempts": [dict(t) for t in reversed(attempts)],
                "claims": claims, "overview": self.overview(slug)}

    def set_compiler(self, slug: str, toolchain: str, flags: list[str] | None = None) -> None:
        proj = self._project(slug)
        if self.is_analysis(proj):
            raise NetworkError("an analysis project doesn't compile: its agents read the target with REA")
        if self.fork_slug(slug):
            raise NetworkError("a fork builds with the project's own compilers and flags")
        cfg = self.cfg(proj)
        toolchain = arch_toolchain(toolchain, cfg.get("arch") or "")
        tc = toolchains.get(toolchain)
        if not flags and cfg.get("platform") == "linux":
            flags = _linux_flags(tc.flags, cfg.get("rom", {}).get("pie", False))
        cfg["compiler"] = {"toolchain": tc.id, "flags": flags or tc.flags, "timeout": 20}
        with self.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
            db.execute("UPDATE functions SET seed=NULL WHERE project_id=? AND status='open'", (proj["id"],))
            self._event(db, proj["id"], None, "compiler", f"{tc.name} {' '.join(cfg['compiler']['flags'])}")

    def chat_agent(self, base: str) -> tuple[Agent, str]:
        """An identity for an agent the user talks to (Claude Code, Codex, ... connected with `decomp mcp`): `base`,
        or base_2, base_3... when another session of the same agent is active right now (never base-2: that's the
        name of a helper session, see local_agent)."""
        base = re.sub(r"[^A-Za-z0-9_.-]+", "-", base).strip("-")[:30] or "chat"
        for n in range(1, 100):
            name = base if n == 1 else f"{base}_{n}"
            row = self.store.one("SELECT id, origin, last_seen FROM agents WHERE name=?", name)
            if row is None or (row["origin"] == "chat" and (row["last_seen"] or 0) < time.time() - 600):
                break
        else:
            raise NetworkError("too many chat sessions at once")
        if row is None:
            token = self.register_agent(name, "you", trusted=True, origin="chat")
        else:
            token = "dn_" + secrets.token_urlsafe(24)
            with self.store.tx() as db:
                db.execute("UPDATE agents SET token_hash=?, last_seen=? WHERE id=?", (_hash_token(token), time.time(), row["id"]))
        return self.authenticate(token), token

    def is_chat(self, agent: Agent) -> bool:
        row = self.store.one("SELECT origin FROM agents WHERE id=?", agent.id)
        return bool(row) and row["origin"] == "chat"

    def _local_token(self, name: str) -> str:
        digest = hmac.new(self._agent_secret.encode(), f"local:{name}".encode(), hashlib.sha256).digest()
        return "dn_" + base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def local_agent(self, name: str) -> tuple[Agent, str]:
        """An agent identity for one runner on this machine (created on first use). A name an agent the user talks
        to had before 0.10.4 (chat identities were numbered like helper sessions) becomes the runner's: a helper
        never gets the chat agent's tools, and the chat agent never takes over the runner's identity.

        The token is derived from the install's agent secret, so it survives app restarts: a helper's MCP bridge
        that reconnects after a restart still authenticates, instead of being treated as an unknown agent."""
        token = self._local_token(name)
        row = self.store.one("SELECT id FROM agents WHERE name=?", name)
        if row is not None:
            with self.store.tx() as db:
                db.execute("UPDATE agents SET token_hash=?, origin=CASE origin WHEN 'chat' THEN 'local' ELSE origin END "
                           "WHERE id=?", (_hash_token(token), row["id"]))
        else:
            with self.store.tx() as db:
                db.execute("INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin) VALUES(?,?,?,?,1,?)",
                           (name, "you", _hash_token(token), time.time(), "local"))
        return self.authenticate(token), token
