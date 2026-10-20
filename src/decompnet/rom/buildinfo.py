"""What built a PC program: its language, compiler and, when the binary records it, the exact version.

C and C++ leave the compiler's version in .comment. Rust leaves rustc's version there too, or the
standard library's /rustc/<hash>/ or /build/rustc-<version>-.../ paths when stripped. Go records the
toolchain version in .go.buildinfo. None of them record the language standard, so C++20 or Rust
2021 cannot be read from the image reliably.
"""

from __future__ import annotations

import re

GO_MAGIC = b"\xff Go buildinf:"
GO_VERSION = re.compile(rb"go1\.\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.]+)?")
RUST_VERSION = re.compile(rb"rustc(?: version)?[ :]+(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?)")
RUST_PATH = re.compile(rb"rustc-(\d+\.\d+(?:\.\d+)?)(?:-([^/\s\x00]+))?")
GCC_VERSION = re.compile(rb"GCC:\s*\([^)]*\)\s*([0-9][0-9A-Za-z.+-]*)")
CLANG_VERSION = re.compile(rb"clang version\s+([0-9][0-9A-Za-z.+-]*)")
# Linker versions that name a Visual C++ release. MSVC 14.x is the 2015-2022 line; the minor
# number separates them (14.0, 14.1x, 14.2x, 14.3x+).
MSVC_RELEASES = {5: "Visual C++ 5.0", 6: "Visual C++ 6.0", 7: "Visual C++ .NET",
                 8: "Visual C++ 2005", 9: "Visual C++ 2008", 10: "Visual C++ 2010",
                 11: "Visual C++ 2012", 12: "Visual C++ 2013"}
MSVC_CXX_MARKERS = (b"??2@", b"??3@", b"??_", b".?AV", b".?AU")


def _text(raw: bytes) -> bytes:
    return raw.replace(b"\0", b"\n")


def _version(data: bytes, comment: bytes, pattern: re.Pattern[bytes]) -> str:
    for blob in (_text(comment), data):
        match = pattern.search(blob)
        if match:
            return match.group(1).decode("ascii", "replace")
    return ""


def _go_version(data: bytes, buildinfo: bytes) -> str:
    """Go writes the toolchain version into .go.buildinfo (and leaves the string in the image)."""
    if not buildinfo and GO_MAGIC not in data:
        return ""
    match = GO_VERSION.search(buildinfo) or GO_VERSION.search(data)
    if not match:
        return ""
    version = match.group(0).decode("ascii", "replace")
    return version[2:] if version.startswith("go1.") else version


def _rust_version(data: bytes, comment: bytes) -> str:
    version = _version(data, comment, RUST_VERSION)
    if version:
        return version
    # A stripped Rust binary keeps the standard library's source paths, for example
    # /rustc/48a229.../library/std/src/... or /build/rustc-1.93-.../. The release number is in
    # the second form; the first only identifies the build.
    if b"/rustc/" in data or b"rustc version" in data or b"rustc-" in data:
        short = ""
        for match in RUST_PATH.finditer(data):
            tail = match.group(2)
            if tail and (full := re.match(rb"\d+\.\d+\.\d+", tail)):
                return full.group(0).decode("ascii", "replace")
            short = short or match.group(1).decode("ascii", "replace")
        return short
    return ""


def _cc(data: bytes, comment: bytes) -> tuple[str, str]:
    """The C/C++ compiler and version. clang links the C library's GCC line too, so prefer clang."""
    clang = _version(data, comment, CLANG_VERSION)
    if clang:
        return "Clang", clang
    gcc = _version(data, comment, GCC_VERSION)
    if gcc:
        return "GCC", gcc
    return "unknown", ""


def _msvc_release(version: str) -> str:
    try:
        major, minor = (int(x) for x in version.split(".", 1))
    except (ValueError, TypeError):
        return ""
    if major == 14:
        return "Visual C++ 2015" if minor < 10 else "Visual C++ 2017" if minor < 20 else (
            "Visual C++ 2019" if minor < 30 else "Visual C++ 2022")
    return MSVC_RELEASES.get(major, "")


def analyze(data: bytes, *, comment: bytes = b"", buildinfo: bytes = b"", symbols=(), cxx: bool = False,
            linker: str = "", hint: str = "") -> dict:
    """Language, compiler and version of a PC program, as far as its bytes record them."""
    go = _go_version(data, buildinfo)
    has_go = bool(buildinfo) or GO_MAGIC in data or bool(go)
    rust = _rust_version(data, comment) if not has_go else ""
    has_rust = bool(rust) or b"rustc version" in data or b"/rustc/" in data or b"rustc-" in data
    if has_go:
        language, compiler, version = "Go", "go", go
    elif has_rust:
        language, compiler, version = "Rust", "rustc", rust
    else:
        language, compiler, version = ("C++" if cxx else "C"), "", ""
        compiler, version = _cc(data, comment)
        if compiler == "unknown":
            compiler = "MSVC" if linker else (hint or "unknown")
        if compiler == "MSVC":
            version = linker
    release = _msvc_release(version) if compiler == "MSVC" else ""
    detail = " ".join(x for x in (release or compiler, "" if release else version) if x)
    if language in ("Go", "Rust"):
        label = f"{language} {version}".strip()
    else:
        label = f"{language} ({detail})" if detail else language
    return {"language": language, "compiler": compiler or "unknown", "version": version,
            "release": release, "label": label, "matchable": language in ("C", "C++")}


def label_from_guess(guess: str, language: str) -> str:
    """Older projects stored only .comment; give them the same short label without re-importing."""
    info = analyze(b"", comment=guess.encode("utf-8", "replace"), cxx=language == "C++")
    if info["compiler"] != "unknown" and info["version"]:
        return info["label"]
    return f"{language} ({guess})" if guess and guess != "unknown" else language


def looks_cxx(symbols, data: bytes = b"") -> bool:
    """C++ symbols or runtime, excluding a C program that only imports a C++ library by accident."""
    names = [s.name for s in symbols]
    if any(n.startswith("?") for n in names):  # MSVC
        return True
    if any(n.startswith("_Z") for n in names):  # Itanium ABI (GCC, Clang, MinGW)
        return True
    if any(("libstdc++" in n.lower() or "libc++" in n.lower() or "msvcp" in n.lower()) for n in names):
        return True
    # A stripped MSVC C++ binary keeps its runtime's decorated names even when the COFF symbols are gone:
    # operator new (??2@...), RTTI descriptors (.?AVtype_info@@), vtables (??_7...).
    return any(marker in data for marker in MSVC_CXX_MARKERS)
