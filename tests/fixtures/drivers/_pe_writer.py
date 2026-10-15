"""Shared helpers for the fixture generators: a tiny x64 code emitter and a
PE32+ writer for inert, unsigned native images. Not a general assembler -
instructions are written as hex by the generators, and this only resolves
RIP-relative operands and lays out sections/imports.
"""
from __future__ import annotations

import struct

IMAGE_BASE = 0x140000000
SECTION_SIZE = 0x1000
FILE_ALIGN = 0x200
HEADERS_SIZE = 0x400


class Asm:
    """Machine code for one function starting at `rva`."""

    def __init__(self, rva: int):
        self.rva = rva
        self.code = bytearray()

    def here(self) -> int:
        return self.rva + len(self.code)

    def raw(self, hexstr: str) -> "Asm":
        self.code += bytes.fromhex(hexstr.replace(" ", ""))
        return self

    def rip(self, prefix_hex: str, target: int, suffix_hex: str = "") -> "Asm":
        """prefix + rel32 + suffix, rel32 measured from the end of the instruction."""
        prefix = bytes.fromhex(prefix_hex.replace(" ", ""))
        suffix = bytes.fromhex(suffix_hex.replace(" ", ""))
        end = self.here() + len(prefix) + 4 + len(suffix)
        self.code += prefix + struct.pack("<i", target - end) + suffix
        return self

    def call(self, target: int) -> "Asm":
        return self.rip("E8", target)

    def jcc32(self, opcode2_hex: str, target: int) -> "Asm":
        """0F 8x rel32 (e.g. "0F 84" = je)."""
        return self.rip(opcode2_hex, target)


def imm32(v: int) -> str:
    return struct.pack("<I", v & 0xFFFFFFFF).hex()


def utf16z(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def unicode_string(buffer_rva: int, text: str) -> bytes:
    """UNICODE_STRING {Length, MaximumLength, pad, Buffer} (x64, 16 bytes)."""
    length = len(text) * 2
    return struct.pack("<HHIQ", length, length + 2, 0, IMAGE_BASE + buffer_rva)


def guid_bytes(d1: int, d2: int, d3: int, d4: bytes) -> bytes:
    return struct.pack("<IHH", d1, d2, d3) + d4


def place(section: bytearray, section_rva: int, rva: int, data: bytes) -> None:
    off = rva - section_rva
    section[off:off + len(data)] = data


def build_imports(rdata: bytearray, rdata_rva: int, at: int,
                  imports: dict[str, list[str]]) -> tuple[dict[str, int], int, int]:
    """Writes an import directory into `rdata` at offset `at`.
    Returns ({function: IAT slot RVA}, import dir RVA, import dir size)."""
    idt_size = (len(imports) + 1) * 20
    cursor = at + idt_size
    iat: dict[str, int] = {}
    for i, (dll, funcs) in enumerate(imports.items()):
        ilt = cursor
        iat_off = ilt + (len(funcs) + 1) * 8
        pos = iat_off + (len(funcs) + 1) * 8
        for j, fn in enumerate(funcs):
            hint_name = struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(hint_name) % 2:
                hint_name += b"\x00"
            rdata[pos:pos + len(hint_name)] = hint_name
            struct.pack_into("<Q", rdata, ilt + j * 8, rdata_rva + pos)
            struct.pack_into("<Q", rdata, iat_off + j * 8, rdata_rva + pos)
            iat[fn] = rdata_rva + iat_off + j * 8
            pos += len(hint_name)
        dll_name = pos
        rdata[pos:pos + len(dll) + 1] = dll.encode() + b"\x00"
        pos += len(dll) + 1
        struct.pack_into("<IIIII", rdata, at + i * 20, rdata_rva + ilt, 0, 0,
                         rdata_rva + dll_name, rdata_rva + iat_off)
        cursor = (pos + 7) & ~7
    return iat, rdata_rva + at, idt_size


def write_pe(path: str, sections: list[tuple[bytes, int, bytes, int]], entry_rva: int,
             import_dir: tuple[int, int], timestamp: int) -> int:
    """sections: (name, rva, content (SECTION_SIZE bytes), characteristics)."""
    size_of_image = max(rva for _, rva, _, _ in sections) + SECTION_SIZE
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), timestamp, 0, 0, 0xF0, 0x0022)
    opt = bytearray(0xF0)
    struct.pack_into("<HBB", opt, 0, 0x20B, 14, 0)
    struct.pack_into("<I", opt, 0x10, entry_rva)
    struct.pack_into("<I", opt, 0x14, sections[0][1])
    struct.pack_into("<Q", opt, 0x18, IMAGE_BASE)
    struct.pack_into("<II", opt, 0x20, SECTION_SIZE, FILE_ALIGN)
    struct.pack_into("<HHHHHH", opt, 0x28, 10, 0, 10, 0, 10, 0)
    struct.pack_into("<II", opt, 0x38, size_of_image, HEADERS_SIZE)
    struct.pack_into("<HH", opt, 0x44, 1, 0x0160)
    struct.pack_into("<QQQQ", opt, 0x48, 0x40000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", opt, 0x6C, 16)
    struct.pack_into("<II", opt, 0x70 + 1 * 8, *import_dir)

    headers = bytearray(HEADERS_SIZE)
    headers[0:0x40] = dos
    headers[0x40:0x44] = b"PE\x00\x00"
    headers[0x44:0x44 + len(coff)] = coff
    opt_off = 0x44 + len(coff)
    headers[opt_off:opt_off + len(opt)] = opt
    sh = opt_off + len(opt)
    raw = HEADERS_SIZE
    body = bytearray()
    for i, (name, rva, content, chars) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", headers, sh + i * 40, name, SECTION_SIZE, rva,
                         len(content), raw, 0, 0, 0, 0, chars)
        body += content
        raw += len(content)
    with open(path, "wb") as f:
        f.write(bytes(headers) + bytes(body))
    return HEADERS_SIZE + len(body)
