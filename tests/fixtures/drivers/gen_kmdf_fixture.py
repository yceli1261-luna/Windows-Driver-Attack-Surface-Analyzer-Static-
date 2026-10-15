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
  RVA 0x1300  EvtDriverDeviceAdd WdfDeviceInitSetIoType(Direct=3),
                                 WdfDeviceInitAssignName(L"\\Device\\DasaKmdf"),
                                 WdfDeviceInitSetCharacteristics(
                                   FILE_DEVICE_SECURE_OPEN),
                                 WdfDeviceInitSetDeviceType(FILE_DEVICE_UNKNOWN),
                                 WdfDeviceCreateSymbolicLink(
                                   L"\\DosDevices\\DasaKmdf"),
                                 WdfDeviceCreateDeviceInterface(
                                   {12345678-1234-5678-9ABC-DEF012345678}),
                                 all via `call [rax+i*8]`;
                                 queue 1 via the CFG thunk: Parallel,
                                 default, EvtIoRead = 0x1520,
                                 EvtIoDeviceControl = 0x1600;
                                 queue 2 via `call [rax+0x4C0]`:
                                 Sequential, not default,
                                 EvtIoInternalDeviceControl = 0x1530
  RVA 0x1500..0x1530  callbacks  `xor eax, eax; ret`
  RVA 0x1540  guard thunk        `jmp rax` (_guard_dispatch_icall_nop)
  RVA 0x1600  EvtIoDeviceControl compares its 5th argument (IoControlCode)
                                 with 0x0022E004 and 0x00222003; both
                                 branch to 0x1628

  .data 0x3000  WDF_BIND_INFO {Size 0x30, L"KmdfLibrary", 1.15.0, 444
                functions, FuncTable = &WdfFunctions_01015 (0x3040)}
  .data 0x3048  WdfDriverGlobals

WDF table indices are from wdffuncenum.h (KMDF 1.33); struct layouts from
wdfdriver.h / wdfio.h / fxldr.h. The file is not loadable (unsigned, no
real code paths) and exists only as a test fixture.

Usage: python gen_kmdf_fixture.py [output.sys]
"""
from __future__ import annotations

import os
import struct
import sys

from _pe_writer import (IMAGE_BASE, SECTION_SIZE, Asm, build_imports, guid_bytes, imm32, place,
                        unicode_string, utf16z, write_pe)

TEXT_RVA, RDATA_RVA, DATA_RVA = 0x1000, 0x2000, 0x3000

BIND_INFO = DATA_RVA + 0x00
WDF_FUNCTIONS = DATA_RVA + 0x40
WDF_GLOBALS = DATA_RVA + 0x48

KMDF_COMPONENT = RDATA_RVA + 0x40
DEVICE_NAME_TEXT = RDATA_RVA + 0x300
LINK_NAME_TEXT = RDATA_RVA + 0x340
US_DEVICE = RDATA_RVA + 0x380
US_LINK = RDATA_RVA + 0x390
INTERFACE_GUID = RDATA_RVA + 0x3A0

FN = {
    "FxDriverEntry": 0x1000,
    "FxDriverEntryWorker": 0x1100,
    "DriverEntry": 0x1200,
    "EvtDriverDeviceAdd": 0x1300,
    "EvtDriverUnload": 0x1500,
    "EvtIoRead": 0x1520,
    "EvtIoInternalDeviceControl": 0x1530,
    "GuardDispatch": 0x1540,
    "EvtIoDeviceControl": 0x1600,
}

# wdffuncenum.h indices
WDF_DEVICE_INIT_SET_IO_TYPE = 61
WDF_DEVICE_INIT_SET_DEVICE_TYPE = 66
WDF_DEVICE_INIT_ASSIGN_NAME = 67
WDF_DEVICE_INIT_SET_CHARACTERISTICS = 70
WDF_DEVICE_CREATE_DEVICE_INTERFACE = 77
WDF_DEVICE_CREATE_SYMBOLIC_LINK = 80
WDF_DRIVER_CREATE = 116
WDF_IO_QUEUE_CREATE = 152


def wdf_call(a: Asm, index: int) -> None:
    """mov rax, [WdfFunctions]; call qword ptr [rax + index*8]"""
    a.rip("48 8B 05", WDF_FUNCTIONS)
    a.raw("FF 90" + imm32(index * 8))


def build_text(iat: dict[str, int]) -> bytes:
    text = bytearray(b"\xCC" * SECTION_SIZE)

    def put(name: str, a: Asm) -> None:
        place(text, TEXT_RVA, FN[name], bytes(a.code))

    a = Asm(FN["FxDriverEntry"])
    a.raw("48 89 5C 24 08 57 48 83 EC 20")   # mov [rsp+8], rbx; push rdi; sub rsp, 0x20
    a.raw("48 8B DA 48 8B F9")               # mov rbx, rdx; mov rdi, rcx
    a.raw("48 8B D3 48 8B CF")               # mov rdx, rbx; mov rcx, rdi
    a.call(FN["FxDriverEntryWorker"])
    a.raw("48 8B 5C 24 30 48 83 C4 20 5F C3")  # mov rbx, [rsp+0x30]; add rsp, 0x20; pop rdi; ret
    put("FxDriverEntry", a)

    a = Asm(FN["FxDriverEntryWorker"])
    a.raw("53 57 48 83 EC 28")               # push rbx; push rdi; sub rsp, 0x28
    a.raw("48 8B DA 48 8B F9")
    a.rip("4C 8D 0D", WDF_GLOBALS)            # lea r9, [WdfDriverGlobals]
    a.rip("4C 8D 05", BIND_INFO)              # lea r8, [WdfBindInfo]
    a.raw("48 8B D3 48 8B CF")
    a.rip("FF 15", iat["WdfVersionBind"])     # call [WdfVersionBind]
    a.raw("48 8B D3 48 8B CF")
    a.call(FN["DriverEntry"])
    a.raw("48 83 C4 28 5F 5B C3")
    put("FxDriverEntryWorker", a)

    # DriverEntry: WdfDriverCreate(Globals, DO, RP, NULL, &config, NULL)
    a = Asm(FN["DriverEntry"])
    a.raw("53 48 83 EC 60")                   # push rbx; sub rsp, 0x60
    a.raw("C7 44 24 30" + imm32(0x20))        # config.Size
    a.rip("48 8D 05", FN["EvtDriverDeviceAdd"])
    a.raw("48 89 44 24 38")                   # config.EvtDriverDeviceAdd (+8)
    a.rip("48 8D 05", FN["EvtDriverUnload"])
    a.raw("48 89 44 24 40")                   # config.EvtDriverUnload (+0x10)
    a.raw("48 8D 44 24 30 48 89 44 24 20")    # 5th arg = &config
    a.raw("48 C7 44 24 28 00000000")          # 6th arg = NULL
    a.raw("45 33 C9 4C 8B C2 48 8B D1")       # xor r9d, r9d; mov r8, rdx; mov rdx, rcx
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.rip("48 8B 05", WDF_FUNCTIONS)
    a.raw("48 8B 80" + imm32(WDF_DRIVER_CREATE * 8))
    a.call(FN["GuardDispatch"])
    a.raw("48 83 C4 60 5B C3")
    put("DriverEntry", a)

    # EvtDriverDeviceAdd(Driver, DeviceInit)
    a = Asm(FN["EvtDriverDeviceAdd"])
    a.raw("55 48 81 EC" + imm32(0x120))       # push rbp; sub rsp, 0x120
    a.raw("48 8D 6C 24 30")                   # lea rbp, [rsp+0x30]
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("41 B8" + imm32(3))                 # IoType = WdfDeviceIoDirect
    wdf_call(a, WDF_DEVICE_INIT_SET_IO_TYPE)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.rip("4C 8D 05", US_DEVICE)              # lea r8, [DeviceName]
    wdf_call(a, WDF_DEVICE_INIT_ASSIGN_NAME)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("41 B8" + imm32(0x100))             # FILE_DEVICE_SECURE_OPEN
    a.raw("41 B1 01")                         # mov r9b, 1 (OrInValues)
    wdf_call(a, WDF_DEVICE_INIT_SET_CHARACTERISTICS)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("41 B8" + imm32(0x22))              # FILE_DEVICE_UNKNOWN
    wdf_call(a, WDF_DEVICE_INIT_SET_DEVICE_TYPE)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.rip("4C 8D 05", US_LINK)                # lea r8, [SymbolicLinkName]
    wdf_call(a, WDF_DEVICE_CREATE_SYMBOLIC_LINK)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.rip("4C 8D 05", INTERFACE_GUID)         # lea r8, [InterfaceGuid]
    a.raw("45 33 C9")
    wdf_call(a, WDF_DEVICE_CREATE_DEVICE_INTERFACE)
    # Queue 1 config at [rbp]
    a.raw("0F 57 C0 0F 11 45 10")             # xorps xmm0, xmm0; movups [rbp+0x10], xmm0
    a.raw("C7 45 00" + imm32(0x60))           # Size
    a.raw("C7 45 04" + imm32(2))              # Parallel
    a.raw("C6 45 0D 01")                      # DefaultQueue = TRUE
    a.rip("48 8D 05", FN["EvtIoDeviceControl"])
    a.raw("48 89 45 28")                      # EvtIoDeviceControl (+0x28)
    a.rip("48 8D 05", FN["EvtIoRead"])
    a.raw("48 89 45 18")                      # EvtIoRead (+0x18)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("33 D2 4C 8D 45 00 45 33 C9")       # xor edx, edx; lea r8, [rbp]; xor r9d, r9d
    a.rip("48 8B 05", WDF_FUNCTIONS)
    a.raw("48 8B 80" + imm32(WDF_IO_QUEUE_CREATE * 8))
    a.call(FN["GuardDispatch"])
    # Queue 2 config at [rbp+0x80]
    a.raw("C7 85" + imm32(0x80) + imm32(0x60))
    a.raw("C7 85" + imm32(0x84) + imm32(1))   # Sequential
    a.raw("C6 85" + imm32(0x8D) + "00")       # DefaultQueue = FALSE
    a.rip("48 8D 05", FN["EvtIoInternalDeviceControl"])
    a.raw("48 89 85" + imm32(0xB0))           # EvtIoInternalDeviceControl (+0x30)
    a.rip("48 8B 0D", WDF_GLOBALS)
    a.raw("4C 8D 85" + imm32(0x80) + "45 33 C9")
    wdf_call(a, WDF_IO_QUEUE_CREATE)
    a.raw("33 C0 48 81 C4" + imm32(0x120) + "5D C3")
    assert a.here() <= FN["EvtDriverUnload"], hex(a.here())
    put("EvtDriverDeviceAdd", a)

    for name in ("EvtDriverUnload", "EvtIoRead", "EvtIoInternalDeviceControl"):
        put(name, Asm(FN[name]).raw("33 C0 C3"))
    put("GuardDispatch", Asm(FN["GuardDispatch"]).raw("FF E0"))

    # EvtIoDeviceControl(Queue, Request, OutLen, InLen, IoControlCode)
    a = Asm(FN["EvtIoDeviceControl"])
    a.raw("48 83 EC 28")                      # sub rsp, 0x28 -> 5th arg at [rsp+0x50]
    a.raw("8B 44 24 50")                      # mov eax, [rsp+0x50]
    ok = FN["EvtIoDeviceControl"] + 0x28
    a.raw("3D" + imm32(0x0022E004)).jcc32("0F 84", ok)
    a.raw("3D" + imm32(0x00222003)).jcc32("0F 84", ok)
    a.raw("B8" + imm32(0xC0000010) + "48 83 C4 28 C3")
    assert a.here() == ok, hex(a.here())
    a.raw("33 C0 48 83 C4 28 C3")
    put("EvtIoDeviceControl", a)
    return bytes(text)


def build_rdata() -> tuple[bytes, dict[str, int], tuple[int, int]]:
    rdata = bytearray(SECTION_SIZE)
    iat, idt_rva, idt_size = build_imports(rdata, RDATA_RVA, 0x100,
                                           {"WDFLDR.SYS": ["WdfVersionBind"], "ntoskrnl.exe": ["DbgPrint"]})
    place(rdata, RDATA_RVA, KMDF_COMPONENT, utf16z("KmdfLibrary"))
    place(rdata, RDATA_RVA, DEVICE_NAME_TEXT, utf16z("\\Device\\DasaKmdf"))
    place(rdata, RDATA_RVA, LINK_NAME_TEXT, utf16z("\\DosDevices\\DasaKmdf"))
    place(rdata, RDATA_RVA, US_DEVICE, unicode_string(DEVICE_NAME_TEXT, "\\Device\\DasaKmdf"))
    place(rdata, RDATA_RVA, US_LINK, unicode_string(LINK_NAME_TEXT, "\\DosDevices\\DasaKmdf"))
    place(rdata, RDATA_RVA, INTERFACE_GUID,
          guid_bytes(0x12345678, 0x1234, 0x5678, bytes.fromhex("9ABCDEF012345678")))
    return bytes(rdata), iat, (idt_rva, idt_size)


def build_data() -> bytes:
    data = bytearray(SECTION_SIZE)
    struct.pack_into("<IIQIIIIQQ", data, 0,
                     0x30, 0, IMAGE_BASE + KMDF_COMPONENT,  # Size, pad, Component
                     1, 15, 0, 444,                          # Version 1.15.0, FuncCount
                     IMAGE_BASE + WDF_FUNCTIONS, 0)          # FuncTable, Module
    return bytes(data)


def build(out: str) -> None:
    rdata, iat, import_dir = build_rdata()
    sections = [
        (b".text", TEXT_RVA, build_text(iat), 0x60000020),
        (b".rdata", RDATA_RVA, rdata, 0x40000040),
        (b".data", DATA_RVA, build_data(), 0xC0000040),
    ]
    size = write_pe(out, sections, FN["FxDriverEntry"], import_dir, timestamp=0x66000000)
    print(f"Wrote {out} ({size} bytes)")


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(__file__), "DASAKmdfSample.sys")
    build(sys.argv[1] if len(sys.argv) > 1 else default)
