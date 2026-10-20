"""Work out what the user picked: an N64 ROM, a PlayStation executable, or a PlayStation disc image."""

from __future__ import annotations

from dataclasses import dataclass, field

import struct
from pathlib import Path

from . import chd, elfexe, gba, n64, overlays, pe, ps2, psx
from .n64 import RomError

PLATFORMS = {"n64": "Nintendo 64", "psx": "PlayStation", "ps2": "PlayStation 2", "gba": "Game Boy Advance",
             "windows": "Windows", "linux": "Linux"}
SMALL = 64 * 1024 * 1024  # ROMs and programs are read whole; disc images are read from disk


@dataclass
class Picked:
    platform: str  # n64 | psx | ps2
    data: bytes  # what we split: a z64 ROM, a PS-X EXE or a PS2 ELF
    filename: str  # name to store it under in the project folder
    info: dict
    big_endian: bool
    overlays: list = field(default_factory=list)  # (name, bytes, load address): code in other files on the disc
    image: object | None = None  # PE/ELF already read by identify(): importing doesn't parse it twice


def _program(data: bytes, name: str = "") -> Picked | None:
    if gba.is_gba(data):
        return Picked("gba", data, "rom.gba", gba.read_info(data), False)
    if data[:4] in n64.MAGIC:
        rom, info = n64.read_info(data)
        return Picked("n64", rom, "rom.z64", info.to_dict() | {"platform": "n64", "gp": 0}, True)
    if data[:8] == b"PS-X EXE":
        exe, info = psx.read_exe(data, name)
        return Picked("psx", exe, "game.exe", info, False)
    if ps2.is_mips_elf(data):
        elf, info = ps2.read_elf(data, name)
        return Picked("ps2", elf, "game.elf", info, False)
    if pe.is_pe(data):
        image = pe.read(data, name)
        return Picked("windows", data, "game.exe", image.info, False, image=image)
    if elfexe.is_x86_elf(data):
        try:
            image = elfexe.read(data, name)
        except elfexe.ElfError as e:
            raise RomError(str(e)) from e
        return Picked("linux", data, "program.elf", image.info, False, image=image)
    return None


def identify(src: bytes | Path, name: str = "") -> Picked:
    """What the user picked: a ROM or program (bytes or a file), or a disc image (read from the file in place)."""
    if isinstance(src, (str, Path)):
        path = Path(src)
        name = name or path.name
        if path.stat().st_size <= SMALL:
            return identify(path.read_bytes(), name)
        with open(path, "rb") as f:
            head = f.read(0x1000)
        if pe.is_pe(head) or elfexe.is_x86_elf(head):  # PC programs are often larger than the in-memory ROM limit
            return identify(path.read_bytes(), name)
        head = head[:8]
        if chd.is_chd(head):  # a compressed disc image: read in place, a hunk at a time
            with chd.Chd(path) as disc:
                if psx.is_disc(disc):
                    return _from_disc(disc)
            raise RomError("this CHD doesn't hold a PlayStation disc this app can read")
        with open(path, "rb") as f:
            if psx.is_disc(f):
                return _from_disc(f)
        raise RomError("this file is too big for a ROM and isn't a disc image this app can read")
    picked = _program(src, name)
    if picked is not None:
        return picked
    if psx.is_disc(src):
        return _from_disc(src)
    if src[:4] == b"\x7fELF":
        raise RomError("this ELF program isn't for x86/x86-64 Linux or a console decomp.wtf can split from scratch yet")
    raise RomError("this isn't a ROM, disc or game program this app can read: pick an N64 ROM (.z64, .n64, .v64), "
                   "a PlayStation 1 or 2 disc image (.bin, .iso, .chd) or its program file (e.g. SLUS_200.00)")


def _from_disc(src) -> Picked:
    raw, boot, platform = psx.from_disc(src)
    picked = _program(raw, boot)
    if picked is None:
        raise RomError(f"the disc's program {boot} isn't a PlayStation executable this app can read")
    if picked.platform == "psx":
        main = (picked.info["load"], picked.info["load"] + picked.info["size"] - 0x800)
    else:
        segs = overlays._elf_segments(raw) or []
        main = (min((a for a, _ in segs), default=0), max((a + len(d) for a, d in segs), default=0))
    try:
        picked.overlays = overlays.find(psx._Disc(src), boot, picked.platform, main)
    except (RomError, struct.error, IndexError):  # an odd disc: the program alone still works
        picked.overlays = []
    return picked
