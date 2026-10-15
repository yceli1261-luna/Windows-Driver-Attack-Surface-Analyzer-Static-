"""Build tests/fixtures/drivers/DASAKmdfSample.sys: an inert synthetic KMDF driver.

The code bytes are written by hand below, so the expected analysis results
are known from this script, independently of DASA:

  RVA 0x1000  FxDriverEntry      /GS-style stub: forwards (DriverObject,
                                 RegistryPath) to FxDriverEntryWorker
  RVA 0x1100  FxDriverEntryWorker calls WDFLDR!WdfVersionBind(DO, RP,
                                 &WdfBindInfo, &WdfDriverGlobals), then
                                 forwards to DriverEntry
  RVA 0x1200  DriverEntry        WdfDriverCreate (index 116) via the CFG
                                 dispatch thunk, WDF_DRIVER_CONFIG on the
                                 stack: EvtDriverDeviceAdd = 0x1300,
                                 EvtDriverUnload = 0x1500
  RVA 0x1300  EvtDriverDeviceAdd WdfDeviceInitSetIoType(..., Direct=3) via
                                 `call [rax+0x1E8]`;
                                 queue 1 via the CFG thunk: Parallel,
                                 default queue, EvtIoRead = 0x1520,
                                 EvtIoDeviceControl = 0x1510;
                                 queue 2 via `call [rax+0x4C0]`:
                                 Sequential, not default,
                                 EvtIoInternalDeviceControl = 0x1530
  RVA 0x1500..0x1530  callbacks  `xor eax, eax; ret`
  RVA 0x1540  guard thunk        `jmp rax` (_guard_dispatch_icall_nop)

  .data 0x3000  WDF_BIND_INFO {Size 0x30, L"KmdfLibrary", 1.15.0, 444
                functions, FuncTable = &WdfFunctions_01015 (0x3040)}
  .data 0x3048  WdfDriverGlobals

WDF table indices are from wdffuncenum.h (KMDF 1.33): WdfDeviceInitSetIoType
61, WdfDriverCreate 116, WdfIoQueueCreate 152. Struct layouts are from
wdfdriver.h / wdfio.h / fxldr.h. The file is not loadable (unsigned, no real
code paths) and exists only as a test fixture.

Usage: python gen_kmdf_fixture.py [output.sys]
"""
from __future__ import annotations

import os
import struct
import sys

IMAGE_BASE = 0x140000000
TEXT_RVA, RDATA_RVA, DATA_RVA = 0x1000, 0x2000, 0x3000
SECTION_SIZE = 0x1000
FILE_ALIGN = 0x200
HEADERS_SIZE = 0x400

BIND_INFO = DATA_RVA + 0x00
WDF_FUNCTIONS = DATA_RVA + 0x40
WDF_GLOBALS = DATA_RVA + 0x48

FN = {
    "FxDriverEntry": 0x1000,
    "FxDriverEntryWorker": 0x1100,
    "DriverEntry": 0x1200,
    "EvtDriverDeviceAdd": 0x1300,
    "EvtDriverUnload": 0x1500,
    "EvtIoDeviceControl": 0x1510,
    "EvtIoRead": 0x1520,
    "EvtIoInternalDeviceControl": 0x1530,
    "GuardDispatch": 0x1540,
}


class Asm:
    """Appends machine code for one function and resolves RIP-relative
    operands against absolute RVAs once the instruction length is known."""

    def __init__(self, rva: int):
        self.rva = rva
        self.code = bytearray()

    def raw(self, hexstr: str) -> "Asm":
        self.code += bytes.fromhex(hexstr.replace(" ", ""))
        return self

    def rip(self, prefix_hex: str, target: int, suffix: bytes = b"") -> "Asm":
        """Instruction = prefix + rel32 (+ suffix); rel32 is from the end."""
        prefix = bytes.fromhex(prefix_hex.replace(" ", ""))
        end = self.rva + len(self.code) + len(prefix) + 4 + len(suffix)
        self.code += prefix + struct.pack("<i", target - end) + suffix
        return self

    def call(self, target: int) -> "Asm":
        return self.rip("E8", target)


def imm32(v: int) -> str:
    return struct.pack("<I", v & 0xFFFFFFFF).hex()


def build_text(iat: dict[str, int]) -> bytes:
    text = bytearray(b"\xCC" * SECTION_SIZE)

    def place(name: str, asm: Asm) -> None:
        off = FN[name] - TEXT_RVA
        text[off:off + len(asm.code)] = asm.code

    # FxDriverEntry
    a = Asm(FN["FxDriverEntry"])
    a.raw("48 89 5C 24 08")      # mov [rsp+8], rbx
    a.raw("57")                  # push rdi
    a.raw("48 83 EC 20")         # sub rsp, 0x20
    a.raw("48 8B DA")            # mov rbx, rdx
    a.raw("48 8B F9")            # mov rdi, rcx
    a.raw("48 8B D3")            # mov rdx, rbx
    a.raw("48 8B CF")            # mov rcx, rdi
    a.call(FN["FxDriverEntryWorker"])
    a.raw("48 8B 5C 24 30")      # mov rbx, [rsp+0x30]
    a.raw("48 83 C4 20")         # add rsp, 0x20
    a.raw("5F")                  # pop rdi
    a.raw("C3")                  # ret
    place("FxDriverEntry", a)

    # FxDriverEntryWorker
    a = Asm(FN["FxDriverEntryWorker"])
    a.raw("53")                  # push rbx
    a.raw("57")                  # push rdi
    a.raw("48 83 EC 28")         # sub rsp, 0x28
    a.raw("48 8B DA")            # mov rbx, rdx
    a.raw("48 8B F9")            # mov rdi, rcx
    a.rip("4C 8D 0D", WDF_GLOBALS)   # lea r9, [WdfDriverGlobals]
    a.rip("4C 8D 05", BIND_INFO)     # lea r8, [WdfBindInfo]
    a.raw("48 8B D3")            # mov rdx, rbx
    a.raw("48 8B CF")            # mov rcx, rdi
    a.rip("FF 15", iat["WdfVersionBind"])  # call [WdfVersionBind]
    a.raw("48 8B D3")            # mov rdx, rbx
    a.raw("48 8B CF")            # mov rcx, rdi
    a.call(FN["DriverEntry"])
    a.raw("48 83 C4 28")         # add rsp, 0x28
    a.raw("5F 5B")               # pop rdi; pop rbx
    a.raw("C3")
    place("FxDriverEntryWorker", a)

    # DriverEntry: WdfDriverCreate(Globals, DO, RP, NULL, &config, NULL)
    a = Asm(FN["DriverEntry"])
    a.raw("53")                  # push rbx
    a.raw("48 83 EC 60")         # sub rsp, 0x60
    a.raw("C7 44 24 30" + imm32(0x20))         # config.Size = 0x20
    a.rip("48 8D 05", FN["EvtDriverDeviceAdd"])  # lea rax, [EvtDriverDeviceAdd]
    a.raw("48 89 44 24 38")      # config.EvtDriverDeviceAdd (+8)
    a.rip("48 8D 05", FN["EvtDriverUnload"])     # lea rax, [EvtDriverUnload]
    a.raw("48 89 44 24 40")      # config.EvtDriverUnload (+0x10)
    a.raw("48 8D 44 24 30")      # lea rax, [rsp+0x30]  (&config)
    a.raw("48 89 44 24 20")      # 5th arg
    a.raw("48 C7 44 24 28 00000000")  # 6th arg = NULL
    a.raw("45 33 C9")            # xor r9d, r9d
    a.raw("4C 8B C2")            # mov r8, rdx
    a.raw("48 8B D1")            # mov rdx, rcx
    a.rip("48 8B 0D", WDF_GLOBALS)     # mov rcx, [WdfDriverGlobals]
    a.rip("48 8B 05", WDF_FUNCTIONS)   # mov rax, [WdfFunctions]
    a.raw("48 8B 80" + imm32(116 * 8))  # mov rax, [rax + WdfDriverCreate*8]
    a.call(FN["GuardDispatch"])
    a.raw("48 83 C4 60")         # add rsp, 0x60
    a.raw("5B C3")               # pop rbx; ret
    place("DriverEntry", a)

    # EvtDriverDeviceAdd(Driver, DeviceInit)
    a = Asm(FN["EvtDriverDeviceAdd"])
    a.raw("55")                          # push rbp
    a.raw("48 81 EC" + imm32(0x120))     # sub rsp, 0x120
    a.raw("48 8D 6C 24 30")              # lea rbp, [rsp+0x30]
    # WdfDeviceInitSetIoType(Globals, DeviceInit, WdfDeviceIoDirect)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("41 B8" + imm32(3))            # mov r8d, 3
    a.rip("48 8B 05", WDF_FUNCTIONS)
    a.raw("FF 90" + imm32(61 * 8))       # call [rax + WdfDeviceInitSetIoType*8]
    # Queue 1 config at [rbp]: zero, then fill
    a.raw("0F 57 C0")                    # xorps xmm0, xmm0
    a.raw("0F 11 45 10")                 # movups [rbp+0x10], xmm0
    a.raw("C7 45 00" + imm32(0x60))      # Size
    a.raw("C7 45 04" + imm32(2))         # DispatchType = Parallel
    a.raw("C6 45 0D 01")                 # DefaultQueue = TRUE
    a.rip("48 8D 05", FN["EvtIoDeviceControl"])
    a.raw("48 89 45 28")                 # EvtIoDeviceControl (+0x28)
    a.rip("48 8D 05", FN["EvtIoRead"])
    a.raw("48 89 45 18")                 # EvtIoRead (+0x18)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("33 D2")                       # xor edx, edx
    a.raw("4C 8D 45 00")                 # lea r8, [rbp]
    a.raw("45 33 C9")                    # xor r9d, r9d
    a.rip("48 8B 05", WDF_FUNCTIONS)
    a.raw("48 8B 80" + imm32(152 * 8))   # mov rax, [rax + WdfIoQueueCreate*8]
    a.call(FN["GuardDispatch"])
    # Queue 2 config at [rbp+0x80]
    a.raw("C7 85" + imm32(0x80) + imm32(0x60))   # Size
    a.raw("C7 85" + imm32(0x84) + imm32(1))      # DispatchType = Sequential
    a.raw("C6 85" + imm32(0x8D) + "00")          # DefaultQueue = FALSE
    a.rip("48 8D 05", FN["EvtIoInternalDeviceControl"])
    a.raw("48 89 85" + imm32(0xB0))              # EvtIoInternalDeviceControl (+0x30)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("4C 8D 85" + imm32(0x80))              # lea r8, [rbp+0x80]
    a.raw("45 33 C9")
    a.rip("48 8B 05", WDF_FUNCTIONS)
    a.raw("FF 90" + imm32(152 * 8))              # call [rax + WdfIoQueueCreate*8]
    a.raw("33 C0")                               # xor eax, eax
    a.raw("48 81 C4" + imm32(0x120))             # add rsp, 0x120
    a.raw("5D C3")                               # pop rbp; ret
    place("EvtDriverDeviceAdd", a)

    for name in ("EvtDriverUnload", "EvtIoDeviceControl", "EvtIoRead", "EvtIoInternalDeviceControl"):
        place(name, Asm(FN[name]).raw("33 C0 C3"))   # xor eax, eax; ret
    place("GuardDispatch", Asm(FN["GuardDispatch"]).raw("FF E0"))  # jmp rax
    return bytes(text)


def build_rdata() -> tuple[bytes, dict[str, int], int, int]:
    """Import directory + L"KmdfLibrary". Returns (bytes, iat_rvas,
    import_dir_rva, import_dir_size)."""
    imports = {"WDFLDR.SYS": ["WdfVersionBind"], "ntoskrnl.exe": ["DbgPrint"]}
    blob = bytearray(SECTION_SIZE)
    idt_off = 0x100
    idt_size = (len(imports) + 1) * 20
    cursor = idt_off + idt_size
    iat: dict[str, int] = {}
    for i, (dll, funcs) in enumerate(imports.items()):
        ilt = cursor
        iat_off = ilt + (len(funcs) + 1) * 8
        names = iat_off + (len(funcs) + 1) * 8
        pos = names
        for j, fn in enumerate(funcs):
            hint_name = struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(hint_name) % 2:
                hint_name += b"\x00"
            blob[pos:pos + len(hint_name)] = hint_name
            struct.pack_into("<Q", blob, ilt + j * 8, RDATA_RVA + pos)
            struct.pack_into("<Q", blob, iat_off + j * 8, RDATA_RVA + pos)
            iat[fn] = RDATA_RVA + iat_off + j * 8
            pos += len(hint_name)
        dll_name = pos
        blob[pos:pos + len(dll) + 1] = dll.encode() + b"\x00"
        pos += len(dll) + 1
        struct.pack_into("<IIIII", blob, idt_off + i * 20, RDATA_RVA + ilt, 0, 0,
                         RDATA_RVA + dll_name, RDATA_RVA + iat_off)
        cursor = (pos + 7) & ~7
    component = "KmdfLibrary".encode("utf-16-le") + b"\x00\x00"
    blob[0x40:0x40 + len(component)] = component
    return bytes(blob), iat, RDATA_RVA + idt_off, idt_size


def build_data() -> bytes:
    blob = bytearray(SECTION_SIZE)
    struct.pack_into("<IIQIIIIQQ", blob, 0,
                     0x30, 0,                      # Size, padding
                     IMAGE_BASE + RDATA_RVA + 0x40,  # Component -> L"KmdfLibrary"
                     1, 15, 0,                     # Version 1.15.0
                     444,                          # FuncCount
                     IMAGE_BASE + WDF_FUNCTIONS,   # FuncTable
                     0)                            # Module
    return bytes(blob)


def build(out: str) -> None:
    rdata, iat, import_rva, import_size = build_rdata()
    text = build_text(iat)
    data = build_data()

    sections = [
        (b".text", TEXT_RVA, text, 0x60000020),
        (b".rdata", RDATA_RVA, rdata, 0x40000040),
        (b".data", DATA_RVA, data, 0xC0000040),
    ]
    size_of_image = DATA_RVA + SECTION_SIZE

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0x66000000, 0, 0, 0xF0, 0x0022)
    opt = bytearray(0xF0)
    struct.pack_into("<HBB", opt, 0, 0x20B, 14, 0)
    struct.pack_into("<I", opt, 0x10, FN["FxDriverEntry"])     # AddressOfEntryPoint
    struct.pack_into("<I", opt, 0x14, TEXT_RVA)                # BaseOfCode
    struct.pack_into("<Q", opt, 0x18, IMAGE_BASE)
    struct.pack_into("<II", opt, 0x20, SECTION_SIZE, FILE_ALIGN)
    struct.pack_into("<HHHHHH", opt, 0x28, 10, 0, 10, 0, 10, 0)
    struct.pack_into("<II", opt, 0x38, size_of_image, HEADERS_SIZE)
    struct.pack_into("<HH", opt, 0x44, 1, 0x0160)              # NATIVE; DYNAMIC_BASE|NX|HIGH_ENTROPY_VA
    struct.pack_into("<QQQQ", opt, 0x48, 0x40000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", opt, 0x6C, 16)                      # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 0x70 + 1 * 8, import_rva, import_size)

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

    with open(out, "wb") as f:
        f.write(bytes(headers) + bytes(body))
    print(f"Wrote {out} ({HEADERS_SIZE + len(body)} bytes)")


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(__file__), "DASAKmdfSample.sys")
    build(sys.argv[1] if len(sys.argv) > 1 else default)
