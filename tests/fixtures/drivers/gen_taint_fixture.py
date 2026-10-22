"""Build tests/fixtures/drivers/DASATaintSample.sys: an inert synthetic WDM
driver whose IOCTL handler passes request data to dangerous operations.

The code bytes are written by hand below, so which data reaches which
operation is known from this script, independently of DASA:

  RVA 0x1000  DriverEntry: IoCreateDevice("\\Device\\DasaTaint"),
              IoCreateSymbolicLink("\\DosDevices\\DasaTaint"),
              MajorFunction[IRP_MJ_DEVICE_CONTROL] = 0x1100
  RVA 0x1100  DeviceControl(DeviceObject, Irp): rbx = Irp,
              code = IrpSp->Parameters.DeviceIoControl.IoControlCode, then
              cmp/je to one case per IOCTL. Every case re-reads what it
              needs from rbx (Irp), so nothing depends on volatile registers
              surviving another case's call.
    0x1200  IOCTL 0x00222000 (BUFFERED): buf = Irp->AssociatedIrp.SystemBuffer;
            MapHelper(*(u64*)buf, *(u32*)(buf+8))
            -> 0x1400 MapHelper calls MmMapIoSpace(rcx, rdx, 0):
               PhysicalAddress and NumberOfBytes come from the request.
    0x1240  IOCTL 0x00222004 (BUFFERED): memcpy(dst = *(void**)(buf+0x10),
            src = buf+0x18, len = IrpSp->Parameters.DeviceIoControl.InputBufferLength):
            Destination is a pointer read from the request, Length is the
            request's input length; Source is the system buffer (fine).
    0x1280  IOCTL 0x00222008 (BUFFERED): ecx/eax/edx = buf[0]/buf[4]/buf[8]; wrmsr
    0x12C0  IOCTL 0x0022200F (NEITHER): p = IrpSp->Parameters.DeviceIoControl.
            Type3InputBuffer; eax = *(u32*)p - a user pointer read without ProbeForRead
    0x1300  IOCTL 0x00222010 (BUFFERED): *(u64*)buf[0x20] = buf[0x28] -
            a write of request data to an address taken from the request
    0x1340  IOCTL 0x00222017 (NEITHER): ProbedHelper(Type3InputBuffer, InputBufferLength)
            -> 0x1440 ProbedHelper: ProbeForRead(p, len, 1), then *(u32*)p -
               the read is after a probe, so it is not an unprobed dereference.
  RVA 0x1480  CreateClose: xor eax, eax; ret

The file is not loadable and exists only as a test fixture.

Usage: python gen_taint_fixture.py [output.sys]
"""
from __future__ import annotations

import os
import sys

from _pe_writer import SECTION_SIZE, Asm, build_imports, imm32, place, utf16z, write_pe

TEXT_RVA, RDATA_RVA, DATA_RVA = 0x1000, 0x2000, 0x3000
DEVICE_TEXT = RDATA_RVA + 0x300
LINK_TEXT = RDATA_RVA + 0x340

FN = {
    "DriverEntry": 0x1000,
    "DeviceControl": 0x1100,
    "MapHelper": 0x1400,
    "ProbedHelper": 0x1440,
    "CreateClose": 0x1480,
}
CASES = {
    0x00222000: 0x1200,  # MmMapIoSpace via MapHelper
    0x00222004: 0x1240,  # memcpy
    0x00222008: 0x1280,  # wrmsr
    0x0022200F: 0x12C0,  # unprobed METHOD_NEITHER read
    0x00222010: 0x1300,  # write-what-where
    0x00222017: 0x1340,  # probed METHOD_NEITHER read
}
EPILOGUE = "33 C0 48 83 C4 40 5B C3"  # xor eax, eax; add rsp, 0x40; pop rbx; ret
LOAD_SYSTEM_BUFFER = "4C 8B 53 18"     # mov r10, [rbx+0x18]   Irp->AssociatedIrp.SystemBuffer
LOAD_IRPSP = "48 8B 83" + imm32(0xB8)  # mov rax, [rbx+0xB8]   IrpSp


def build_text(iat: dict[str, int]) -> bytes:
    text = bytearray(b"\xCC" * SECTION_SIZE)

    def put(rva: int, a: Asm) -> None:
        place(text, TEXT_RVA, rva, bytes(a.code))

    a = Asm(FN["DriverEntry"])
    a.raw("53 57 48 81 EC" + imm32(0x98))         # push rbx; push rdi; sub rsp, 0x98
    a.raw("48 8B F9")                             # mov rdi, rcx (DriverObject)
    a.raw("48 8D 4C 24 40")                       # lea rcx, [rsp+0x40]   &DeviceName
    a.rip("48 8D 15", DEVICE_TEXT)
    a.rip("FF 15", iat["RtlInitUnicodeString"])
    a.raw("48 8D 44 24 50 48 89 44 24 30")        # 7th arg = &DevObj
    a.raw("C6 44 24 28 00")                       # Exclusive = FALSE
    a.raw("C7 44 24 20" + imm32(0))               # Characteristics = 0
    a.raw("41 B9" + imm32(0x22))                  # FILE_DEVICE_UNKNOWN
    a.raw("4C 8D 44 24 40")                       # &DeviceName
    a.raw("33 D2 48 8B CF")                       # xor edx, edx; mov rcx, rdi
    a.rip("FF 15", iat["IoCreateDevice"])
    a.raw("48 8D 4C 24 60")                       # &LinkName
    a.rip("48 8D 15", LINK_TEXT)
    a.rip("FF 15", iat["RtlInitUnicodeString"])
    a.raw("48 8D 4C 24 60 48 8D 54 24 40")        # &LinkName, &DeviceName
    a.rip("FF 15", iat["IoCreateSymbolicLink"])
    a.rip("48 8D 05", FN["CreateClose"])
    a.raw("48 89 47 70")                          # MajorFunction[IRP_MJ_CREATE]
    a.raw("48 89 87" + imm32(0x80))               # MajorFunction[IRP_MJ_CLOSE]
    a.rip("48 8D 05", FN["DeviceControl"])
    a.raw("48 89 87" + imm32(0xE0))               # MajorFunction[IRP_MJ_DEVICE_CONTROL]
    a.raw("33 C0 48 81 C4" + imm32(0x98) + "5F 5B C3")
    put(FN["DriverEntry"], a)

    a = Asm(FN["DeviceControl"])
    a.raw("53 48 83 EC 40")                       # push rbx; sub rsp, 0x40
    a.raw("48 8B DA")                             # mov rbx, rdx (Irp)
    a.raw("48 8B 82" + imm32(0xB8))               # mov rax, [rdx+0xB8]  IrpSp
    a.raw("8B 48 18")                             # mov ecx, [rax+0x18]  IoControlCode
    for code, target in CASES.items():
        a.raw("81 F9" + imm32(code)).jcc32("0F 84", target)  # cmp ecx, code; je case
    a.raw(EPILOGUE)
    assert a.here() <= min(CASES.values()), hex(a.here())
    put(FN["DeviceControl"], a)

    def case(code: int, body: Asm) -> None:
        body.raw(EPILOGUE)
        assert body.here() <= CASES[code] + 0x40, hex(body.here())
        put(CASES[code], body)

    a = Asm(CASES[0x00222000]).raw(LOAD_SYSTEM_BUFFER)
    a.raw("49 8B 0A")                             # mov rcx, [r10]       PhysicalAddress
    a.raw("41 8B 52 08")                          # mov edx, [r10+8]     NumberOfBytes
    a.call(FN["MapHelper"])
    case(0x00222000, a)

    a = Asm(CASES[0x00222004]).raw(LOAD_SYSTEM_BUFFER).raw(LOAD_IRPSP)
    a.raw("44 8B 40 10")                          # mov r8d, [rax+0x10]  InputBufferLength
    a.raw("49 8B 4A 10")                          # mov rcx, [r10+0x10]  dst from the request
    a.raw("49 8D 52 18")                          # lea rdx, [r10+0x18]  src = system buffer
    a.rip("FF 15", iat["memcpy"])
    case(0x00222004, a)

    a = Asm(CASES[0x00222008]).raw(LOAD_SYSTEM_BUFFER)
    a.raw("41 8B 0A")                             # mov ecx, [r10]
    a.raw("41 8B 42 04")                          # mov eax, [r10+4]
    a.raw("41 8B 52 08")                          # mov edx, [r10+8]
    a.raw("0F 30")                                # wrmsr
    case(0x00222008, a)

    a = Asm(CASES[0x0022200F]).raw(LOAD_IRPSP)
    a.raw("48 8B 48 20")                          # mov rcx, [rax+0x20]  Type3InputBuffer
    a.raw("8B 01")                                # mov eax, [rcx]       no ProbeForRead
    case(0x0022200F, a)

    a = Asm(CASES[0x00222010]).raw(LOAD_SYSTEM_BUFFER)
    a.raw("49 8B 42 20")                          # mov rax, [r10+0x20]  address from the request
    a.raw("49 8B 4A 28")                          # mov rcx, [r10+0x28]  value from the request
    a.raw("48 89 08")                             # mov [rax], rcx
    case(0x00222010, a)

    a = Asm(CASES[0x00222017]).raw(LOAD_IRPSP)
    a.raw("48 8B 48 20")                          # mov rcx, [rax+0x20]  Type3InputBuffer
    a.raw("8B 50 10")                             # mov edx, [rax+0x10]  InputBufferLength
    a.call(FN["ProbedHelper"])
    case(0x00222017, a)

    a = Asm(FN["MapHelper"])
    a.raw("48 83 EC 28")                          # sub rsp, 0x28
    a.raw("45 33 C0")                             # xor r8d, r8d         MmNonCached
    a.rip("FF 15", iat["MmMapIoSpace"])
    a.raw("48 83 C4 28 C3")
    put(FN["MapHelper"], a)

    a = Asm(FN["ProbedHelper"])
    a.raw("57 48 83 EC 20")                       # push rdi; sub rsp, 0x20
    a.raw("48 8B F9")                             # mov rdi, rcx
    a.raw("41 B8" + imm32(1))                     # Alignment = 1
    a.rip("FF 15", iat["ProbeForRead"])           # ProbeForRead(p, len, 1)
    a.raw("8B 07")                                # mov eax, [rdi]
    a.raw("48 83 C4 20 5F C3")
    put(FN["ProbedHelper"], a)

    put(FN["CreateClose"], Asm(FN["CreateClose"]).raw("33 C0 C3"))
    return bytes(text)


def build_rdata() -> tuple[bytes, dict[str, int], tuple[int, int]]:
    rdata = bytearray(SECTION_SIZE)
    iat, idt_rva, idt_size = build_imports(
        rdata, RDATA_RVA, 0x100,
        {"ntoskrnl.exe": ["RtlInitUnicodeString", "IoCreateDevice", "IoCreateSymbolicLink",
                          "MmMapIoSpace", "memcpy", "ProbeForRead"]})
    place(rdata, RDATA_RVA, DEVICE_TEXT, utf16z("\\Device\\DasaTaint"))
    place(rdata, RDATA_RVA, LINK_TEXT, utf16z("\\DosDevices\\DasaTaint"))
    return bytes(rdata), iat, (idt_rva, idt_size)


def build(out: str) -> None:
    rdata, iat, import_dir = build_rdata()
    sections = [
        (b".text", TEXT_RVA, build_text(iat), 0x60000020),
        (b".rdata", RDATA_RVA, rdata, 0x40000040),
        (b".data", DATA_RVA, bytes(SECTION_SIZE), 0xC0000040),
    ]
    size = write_pe(out, sections, FN["DriverEntry"], import_dir, timestamp=0x66100000)
    print(f"Wrote {out} ({size} bytes)")


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(__file__), "DASATaintSample.sys")
    build(sys.argv[1] if len(sys.argv) > 1 else default)
