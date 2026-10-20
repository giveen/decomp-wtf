"""Windows PE targets: reading functions out of an executable, and matching compiled C against them.

The fixture is built with the MinGW-w64 GCC already on the machine, so both sides are real compiler
output: the executable is split by decomp.wtf, the candidate is compiled by the same compiler with the
toolchain's flags, and the x86 matcher has to accept it byte for byte.
"""

import shutil
import subprocess
import sys
import json
from pathlib import Path

import pytest

from decompnet import coffobj
from decompnet.app.engine import RomNetwork
from decompnet.rom import pe

CC = shutil.which("x86_64-w64-mingw32-gcc")
FLAGS = ["-O2", "-ffreestanding", "-ffunction-sections", "-fdata-sections", "-fno-asynchronous-unwind-tables",
         "-fno-unwind-tables", "-fno-stack-protector", "-fno-ident", "-fno-pic", "-fno-pie", "-mno-stack-arg-probe"]

pytestmark = pytest.mark.skipif(CC is None, reason="needs x86_64-w64-mingw32-gcc")
CXX = shutil.which("x86_64-w64-mingw32-g++")

SOURCE = r"""
__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int mul3(int a) { return add(a, a) * 3; }
int g_counter;
__attribute__((noinline)) int bump(int n) { g_counter += n; return g_counter; }
__attribute__((noinline)) int twice(int n) { return mul3(n) + 1; }
void _start(void) { g_counter = bump(twice(2)); }
"""


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    work = tmp_path_factory.mktemp("pe")
    (work / "game.c").write_text(SOURCE)
    exe, obj = work / "game.exe", work / "game.o"
    subprocess.run([CC, *FLAGS, "-nostdlib", "-Wl,--entry,_start", "-Wl,--subsystem,console", "-o", str(exe),
                    str(work / "game.c")], check=True)
    subprocess.run([CC, *FLAGS, "-c", "-o", str(obj), str(work / "game.c")], check=True)
    return exe, obj


def test_reads_functions_and_addresses(built):
    exe, _obj = built
    image = pe.read(exe.read_bytes(), "game.exe")
    assert image.arch == "x86_64" and image.pe32_plus
    names = {f.name for f in image.functions}
    assert {"add", "mul3", "bump", "twice", "_start"} <= names
    bump = next(f for f in image.functions if f.name == "bump")
    assert bump.vram == next(s.address for s in image.symbols if s.name == "bump")
    assert {r[1] for r in bump.refs} == {4}  # AMD64 REL32
    assert all(image.info["size"] > 0 for _ in [0])


def test_coff_relocations_point_at_named_symbols(built):
    _exe, obj = built
    fn = coffobj.extract_function(obj.read_bytes(), "bump")
    assert fn is not None and fn.arch == "x86_64" and len(fn.code) == 15
    assert [r.symbol for r in fn.relocs] == ["g_counter", "g_counter"]
    assert [r.offset for r in fn.relocs] == [2, 10]


def test_import_and_match_through_the_engine(built):
    exe, _obj = built
    net = RomNetwork(built[0].parent / "decomp.db", built[0].parent)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game.exe", log=lambda *_: None)
    ov = net.overview(slug)
    assert ov["platform"] == "windows" and ov["platform_name"] == "Windows"
    assert ov["functions"] >= 4 and ov["library"] >= 1 and ov["compiler"]["toolchain"] == "mingw-x86_64"
    assert ov["source_language"] == "C" and ov["source_ext"] == ".c"
    agent, _ = net.local_agent("windows-tester")
    assert "MATCH" in net.compile_and_diff(agent, "add", "int add(int a, int b) { return a + b; }", slug)
    assert "MATCH" in net.compile_and_diff(
        agent, "bump", "int g_counter;\nint bump(int n) { g_counter += n; return g_counter; }", slug)
    # A call to another function is a relocation too: the target's bytes say exactly which address.
    text = net.compile_and_diff(agent, "twice", "int mul3(int a);\nint twice(int n) { return mul3(n) + 1; }", slug)
    assert "MATCH" in text, text
    # A different constant is a real difference, not a relocation.
    text = net.compile_and_diff(agent, "add", "int add(int a, int b) { return a - b; }", slug)
    assert "MATCH" not in text
    assert "bytes differ" in text or "different" in text


def test_xrefs_use_relocations(built):
    exe, _obj = built
    net = RomNetwork(exe.parent / "x.db", exe.parent)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game.exe", log=lambda *_: None)
    proj = net.store.one("SELECT * FROM projects WHERE slug=?", slug)
    x = net.xrefs(proj)
    twice = net.store.one("SELECT * FROM functions WHERE project_id=? AND name='twice'", proj["id"])
    mul3 = net.store.one("SELECT * FROM functions WHERE project_id=? AND name='mul3'", proj["id"])
    assert mul3["vram"] in x["calls"].get(twice["vram"], set())


def test_import_requires_confirmation(built):
    from decompnet.network import NetworkError

    exe, _obj = built
    net = RomNetwork(exe.parent / "no.db", exe.parent)
    with pytest.raises(NetworkError, match="legally obtained"):
        net.import_rom(exe.read_bytes(), name="game.exe", log=lambda *_: None)


CC32 = shutil.which("i686-w64-mingw32-gcc")


@pytest.mark.skipif(CC32 is None, reason="needs i686-w64-mingw32-gcc")
def test_32_bit_functions_and_absolute_globals(tmp_path):
    src = tmp_path / "game32.c"
    src.write_text("int add(int a, int b) { return a + b; }\nint g_counter;\n"
                   "int bump(int n) { g_counter += n; return g_counter; }\n"
                   "void _start(void) { g_counter = bump(2); }\n")
    exe = tmp_path / "game32.exe"
    flags = [f for f in FLAGS if f not in ("-fno-pic", "-fno-pie")]
    subprocess.run([CC32, *flags, "-nostdlib", "-Wl,--entry,_start", "-Wl,--subsystem,console", "-o", str(exe),
                    str(src)], check=True)
    net = RomNetwork(tmp_path / "d.db", tmp_path)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game32.exe", log=lambda *_: None)
    image = pe.read(exe.read_bytes(), "game32.exe")
    assert image.arch == "x86" and {f.name for f in image.functions} >= {"add", "bump"}
    agent, _ = net.local_agent("x86-tester")
    assert "MATCH" in net.compile_and_diff(agent, "add", "int add(int a, int b) { return a + b; }", slug)
    assert "MATCH" in net.compile_and_diff(
        agent, "bump", "int g_counter;\nint bump(int n) { g_counter += n; return g_counter; }", slug)


@pytest.mark.skipif(CXX is None, reason="needs x86_64-w64-mingw32-g++")
def test_cxx_programs_use_cpp_toolchain_and_language(tmp_path):
    src = tmp_path / "game.cpp"
    src.write_text("namespace demo { __attribute__((noinline)) int add(int a, int b) { return a + b; } }\n"
                   "void _start(void) { demo::add(1, 2); }\n")
    exe = tmp_path / "game-cxx.exe"
    subprocess.run([CXX, *FLAGS, "-nostdlib", "-Wl,--entry,_start", "-Wl,--subsystem,console", "-o", str(exe),
                    str(src)], check=True)
    net = RomNetwork(tmp_path / "cxx.db", tmp_path)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game-cxx.exe", log=lambda *_: None)
    ov = net.overview(slug)
    assert ov["compiler"]["toolchain"] == "mingwxx-x86_64"
    assert ov["source_language"] == "C++" and ov["source_ext"] == ".cpp"
    target = net.store.one(
        "SELECT name FROM functions WHERE project_id=(SELECT id FROM projects WHERE slug=?) "
        "AND name LIKE '_ZN4demo3addE%'", slug)["name"]
    agent, _ = net.local_agent("cxx-tester")
    text = net.compile_and_diff(agent, target, "namespace demo { int add(int a, int b) { return a + b; } }", slug)
    assert "MATCH" in text, text


def test_library_functions_are_marked_and_never_claimed(built):
    from decompnet.network import NetworkError

    exe, _obj = built
    net = RomNetwork(exe.parent / "lib.db", exe.parent)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game.exe", log=lambda *_: None)
    rows = {r["name"]: r for r in net.function_map(slug)}
    assert rows["_start"]["status"] == "library" and rows["_start"]["library"] == "CRT"
    assert net.overview(slug)["library"] >= 1
    agent, _ = net.local_agent("lib-tester")
    with pytest.raises(NetworkError, match="library"):
        net.claim(agent, slug, "_start")


def test_detected_flags_can_be_applied_and_still_match(built):
    exe, _obj = built
    net = RomNetwork(exe.parent / "flags.db", exe.parent)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game.exe", log=lambda *_: None)
    ov = net.overview(slug)
    suggested = ov["detected"]["suggested_flags"]
    assert suggested
    net.set_compiler(slug, ov["compiler"]["toolchain"], suggested)
    agent, _ = net.local_agent("flags-tester")
    assert "MATCH" in net.compile_and_diff(agent, "add", "int add(int a, int b) { return a + b; }", slug)


def test_data_symbols_are_listed_and_counted(built):
    exe, _obj = built
    net = RomNetwork(exe.parent / "data.db", exe.parent)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game.exe", log=lambda *_: None)
    rows = net.data_symbols(slug)
    assert any(r["name"] == "g_counter" and r["address"] for r in rows)
    assert net.overview(slug)["data"] == len(rows)
    assert net.data_symbols(slug, query="g_counter")


def test_pc_export_is_a_cmake_project_with_a_working_judge(built, tmp_path):
    import os
    import subprocess
    import sys

    exe, _obj = built
    net = RomNetwork(exe.parent / "pc-export.db", exe.parent)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game.exe", log=lambda *_: None)
    agent, _ = net.local_agent("pc-export")
    assert "MATCH" in net.compile_and_diff(agent, "add", "int add(int a, int b) { return a + b; }", slug)
    assert "MATCH" in net.compile_and_diff(agent, "bump", "int g_counter;\nint bump(int n) { g_counter += n; return g_counter; }", slug)
    res = net.export_rom(slug)
    out = Path(res["path"])
    assert out.is_dir() and res["kind"] == "pc" and res["matched"] >= 2
    for name in ("CMakeLists.txt", "compile_commands.json", "include/context.h", "judge.py", "build.json",
                 "baserom.exe"):
        assert (out / name).is_file(), name
    assert (out / "src" / "add.c").is_file()
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent / "src"))
    check = subprocess.run([sys.executable, "judge.py", "add"], cwd=out, env=env, capture_output=True, text=True)
    assert check.returncode == 0 and "MATCH" in check.stdout, check.stdout + check.stderr
    all_check = subprocess.run([sys.executable, "judge.py", "--all"], cwd=out, env=env, capture_output=True, text=True)
    assert all_check.returncode == 0, all_check.stdout + all_check.stderr


def test_runtime_trace_maps_addresses_and_names_to_functions(built, tmp_path):
    exe, _obj = built
    net = RomNetwork(exe.parent / "trace.db", exe.parent)
    slug = net.import_rom(exe.read_bytes(), confirmed=True, name="game.exe", log=lambda *_: None)
    image = pe.read(exe.read_bytes(), exe.name)
    add = next(f.vram for f in image.functions if f.name == "add")
    bump = next(f.vram for f in image.functions if f.name == "bump")
    trace = tmp_path / "coverage.csv"
    trace.write_text(f"address,count\n0x{add:X},3\n0x{bump + 0x2:X},5\n0xDEADBEEF,1\n")
    result = net.import_trace(slug, str(trace))
    assert result["hits"] == 8 and result["functions"] == 2 and result["unmatched"] == 1
    hot = {r["name"]: r["hits"] for r in net.hot_functions(slug)}
    assert hot["add"] == 3 and hot["bump"] == 5
    assert net.overview(slug)["traced"] == 2 and net.overview(slug)["hits"] == 8
    rows = {r["name"]: r for r in net.function_map(slug)}
    assert rows["add"]["hits"] == 3
    again = net.import_trace(slug, str(trace))
    assert again["hits"] == 8 and net.hot_functions(slug)[0]["hits"] in (6, 10)
