"""Build tests/fixtures/drivers/DASAWdmSample.sys: an inert synthetic WDM driver.

The code bytes are written by hand below, so the expected analysis results
are known from this script, independently of DASA:

  RVA 0x1000  DriverEntry (the PE entry point)
              RtlInitUnicodeString(&DeviceName, L"\\Device\\DasaWdm")
              IoCreateDevice(DO, 0, &DeviceName, FILE_DEVICE_UNKNOWN (0x22),
                             0 (no FILE_DEVICE_SECURE_OPEN), FALSE, &DevObj)
              RtlInitUnicodeString(&LinkName, L"\\DosDevices\\DasaWdm")
              IoCreateSymbolicLink(&LinkName, &DeviceName)
              RtlInitUnicodeString(&RoutineName, L"ZwQuerySystemInformation")
              MmGetSystemRoutineAddress(&RoutineName)
              MajorFunction[IRP_MJ_CREATE] = MajorFunction[IRP_MJ_CLOSE] = 0x1400
              MajorFunction[IRP_MJ_DEVICE_CONTROL] = 0x1200
              DriverUnload = 0x1410
  RVA 0x1200  DeviceControl(DeviceObject, Irp)
              IrpSp = Irp->Tail.Overlay.CurrentStackLocation      ([rdx+0xB8])
              decoy: InputBufferLength < 0x10000 -> fail          ([rax+0x10])
              code  = IrpSp->Parameters.DeviceIoControl.IoControlCode ([rax+0x18])
              sub chain: 0x00222000 -> 0x1260, 0x00222004 -> 0x1270,
                         0x00222008 -> 0x1280
              jump table over code - 0x00222008 in 0..0x20, i.e. IOCTL codes
                0x00222008..0x00222028 (cases not followed)
              default: Helper(DeviceObject, code)
  RVA 0x1300  Helper: code == 0x0022E00B (METHOD_NEITHER,
              FILE_READ|WRITE_ACCESS) -> 0x1312, which calls
              MmMapIoSpace and executes `wrmsr` and `in al, dx`
              (so these are reachable from IRP_MJ_DEVICE_CONTROL)
  RVA 0x1400  CreateClose: xor eax, eax; ret
  RVA 0x1410  DriverUnload: ret

The file is not loadable (unsigned, no real code paths) and exists only as
a test fixture.

Usage: python gen_wdm_fixture.py [output.sys]
"""
from __future__ import annotations

import os
import struct
import sys

from _pe_writer import IMAGE_BASE, SECTION_SIZE, Asm, build_imports, imm32, place, utf16z, write_pe

TEXT_RVA, RDATA_RVA, DATA_RVA = 0x1000, 0x2000, 0x3000

DEVICE_TEXT = RDATA_RVA + 0x300
LINK_TEXT = RDATA_RVA + 0x340
ROUTINE_TEXT = RDATA_RVA + 0x380
JUMP_TABLE = RDATA_RVA + 0x400

FN = {
    "DriverEntry": 0x1000,
    "DeviceControl": 0x1200,
    "Helper": 0x1300,
    "CreateClose": 0x1400,
    "DriverUnload": 0x1410,
}
CASE_A, CASE_B, CASE_C, FAIL = 0x1260, 0x1270, 0x1280, 0x1290


def build_text(iat: dict[str, int]) -> bytes:
    text = bytearray(b"\xCC" * SECTION_SIZE)

    def put(rva: int, a: Asm) -> None:
        place(text, TEXT_RVA, rva, bytes(a.code))

    a = Asm(FN["DriverEntry"])
    a.raw("53 57 48 81 EC" + imm32(0x98))         # push rbx; push rdi; sub rsp, 0x98
    a.raw("48 8B F9")                             # mov rdi, rcx (DriverObject)
    a.raw("48 8D 4C 24 40")                       # lea rcx, [rsp+0x40]   &DeviceName
    a.rip("48 8D 15", DEVICE_TEXT)                # lea rdx, [L"\\Device\\DasaWdm"]
    a.rip("FF 15", iat["RtlInitUnicodeString"])
    a.raw("48 8D 44 24 50 48 89 44 24 30")        # 7th arg = &DevObj
    a.raw("C6 44 24 28 00")                       # 6th arg Exclusive = FALSE
    a.raw("C7 44 24 20" + imm32(0))               # 5th arg Characteristics = 0
    a.raw("41 B9" + imm32(0x22))                  # DeviceType = FILE_DEVICE_UNKNOWN
    a.raw("4C 8D 44 24 40")                       # lea r8, [rsp+0x40]   &DeviceName
    a.raw("33 D2 48 8B CF")                       # xor edx, edx; mov rcx, rdi
    a.rip("FF 15", iat["IoCreateDevice"])
    a.raw("48 8D 4C 24 60")                       # lea rcx, [rsp+0x60]   &LinkName
    a.rip("48 8D 15", LINK_TEXT)
    a.rip("FF 15", iat["RtlInitUnicodeString"])
    a.raw("48 8D 4C 24 60 48 8D 54 24 40")        # &LinkName, &DeviceName
    a.rip("FF 15", iat["IoCreateSymbolicLink"])
    a.raw("48 8D 4C 24 70")                       # lea rcx, [rsp+0x70]   &RoutineName
    a.rip("48 8D 15", ROUTINE_TEXT)
    a.rip("FF 15", iat["RtlInitUnicodeString"])
    a.raw("48 8D 4C 24 70")
    a.rip("FF 15", iat["MmGetSystemRoutineAddress"])
    a.rip("48 8D 05", FN["CreateClose"])
    a.raw("48 89 47 70")                          # MajorFunction[IRP_MJ_CREATE]
    a.raw("48 89 87" + imm32(0x80))               # MajorFunction[IRP_MJ_CLOSE]
    a.rip("48 8D 05", FN["DeviceControl"])
    a.raw("48 89 87" + imm32(0xE0))               # MajorFunction[IRP_MJ_DEVICE_CONTROL]
    a.rip("48 8D 05", FN["DriverUnload"])
    a.raw("48 89 47 68")                          # DriverUnload
    a.raw("33 C0 48 81 C4" + imm32(0x98) + "5F 5B C3")
    put(FN["DriverEntry"], a)

    a = Asm(FN["DeviceControl"])
    a.raw("48 83 EC 28")                          # sub rsp, 0x28
    a.raw("48 8B 82" + imm32(0xB8))               # mov rax, [rdx+0xB8]  IrpSp
    a.raw("81 78 10" + imm32(0x10000))            # cmp dword ptr [rax+0x10], 0x10000  (decoy)
    a.jcc32("0F 82", FAIL)                        # jb Fail
    a.raw("8B 48 18")                             # mov ecx, [rax+0x18]  IoControlCode
    a.raw("81 E9" + imm32(0x222000)).jcc32("0F 84", CASE_A)
    a.raw("83 E9 04").jcc32("0F 84", CASE_B)
    a.raw("83 E9 04").jcc32("0F 84", CASE_C)
    default = a.here() + 3 + 6 + 7 + 4
    a.raw("83 F9 20").jcc32("0F 87", default)     # cmp ecx, 0x20; ja Default
    a.rip("4C 8D 05", JUMP_TABLE)                 # lea r8, [table]
    a.raw("41 FF 24 C8")                          # jmp qword ptr [r8 + rcx*8]
    assert a.here() == default, hex(a.here())
    a.raw("8B 50 18")                             # mov edx, [rax+0x18]  IoControlCode
    a.call(FN["Helper"])
    a.raw("48 83 C4 28 C3")
    assert a.here() <= CASE_A, hex(a.here())
    put(FN["DeviceControl"], a)
    for rva, status in ((CASE_A, 0), (CASE_B, 1), (CASE_C, 2), (FAIL, 0xC000000D)):
        # mov eax, status; add rsp, 0x28; ret
        put(rva, Asm(rva).raw("B8" + imm32(status) + "48 83 C4 28 C3"))

    a = Asm(FN["Helper"])
    a.raw("81 FA" + imm32(0x0022E00B))            # cmp edx, 0x0022E00B
    a.jcc32("0F 84", FN["Helper"] + 0x12)
    a.raw("33 C0 C3 90 90 90")                    # xor eax, eax; ret
    assert a.here() == FN["Helper"] + 0x12, hex(a.here())
    a.raw("48 83 EC 28")                          # sub rsp, 0x28
    a.raw("33 C9 BA" + imm32(0x1000) + "45 33 C0")  # PhysicalAddress 0, 0x1000 bytes, MmNonCached
    a.rip("FF 15", iat["MmMapIoSpace"])
    a.raw("48 83 C4 28")
    a.raw("33 C9 0F 30")                          # xor ecx, ecx; wrmsr
    a.raw("EC")                                   # in al, dx
    a.raw("B8" + imm32(1) + "C3")
    assert a.here() <= FN["CreateClose"], hex(a.here())
    put(FN["Helper"], a)

    put(FN["CreateClose"], Asm(FN["CreateClose"]).raw("33 C0 C3"))
    put(FN["DriverUnload"], Asm(FN["DriverUnload"]).raw("C3"))
    return bytes(text)


def build_rdata() -> tuple[bytes, dict[str, int], tuple[int, int]]:
    rdata = bytearray(SECTION_SIZE)
    iat, idt_rva, idt_size = build_imports(
        rdata, RDATA_RVA, 0x100,
        {"ntoskrnl.exe": ["RtlInitUnicodeString", "IoCreateDevice", "IoCreateSymbolicLink",
                          "IofCompleteRequest", "MmMapIoSpace", "MmGetSystemRoutineAddress"]})
    place(rdata, RDATA_RVA, DEVICE_TEXT, utf16z("\\Device\\DasaWdm"))
    place(rdata, RDATA_RVA, LINK_TEXT, utf16z("\\DosDevices\\DasaWdm"))
    place(rdata, RDATA_RVA, ROUTINE_TEXT, utf16z("ZwQuerySystemInformation"))
    for i in range(0x21):
        struct.pack_into("<Q", rdata, JUMP_TABLE - RDATA_RVA + i * 8, IMAGE_BASE + CASE_C)
    return bytes(rdata), iat, (idt_rva, idt_size)


def build(out: str) -> None:
    rdata, iat, import_dir = build_rdata()
    sections = [
        (b".text", TEXT_RVA, build_text(iat), 0x60000020),
        (b".rdata", RDATA_RVA, rdata, 0x40000040),
        (b".data", DATA_RVA, bytes(SECTION_SIZE), 0xC0000040),
    ]
    size = write_pe(out, sections, FN["DriverEntry"], import_dir, timestamp=0x66000000)
    print(f"Wrote {out} ({size} bytes)")


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(__file__), "DASAWdmSample.sys")
    build(sys.argv[1] if len(sys.argv) > 1 else default)
