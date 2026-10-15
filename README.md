# DASA v2 (C++20 / Qt 6)

Native rewrite of the Driver Attack Surface Analyzer. See
`docs/DASA_V2_ARCHITECTURE.md` for the module layout and rationale, and the
product brief in the project thread for the full phase plan. The original
Python implementation lives at the repository root (`main.py`, `analysis/`,
`parser/`, etc.) and is left untouched — it's the behavioral reference this
rewrite is validated against, not code being migrated line-by-line.

## Status

**Phase 1 — application shell (done).** CMake project, Qt 6 window with
the dock layout (one dock per WORKSPACE/RESEARCH/DYNAMIC/DATABASE/REPORTS
view from the brief), persisted layout, dark theme, driver loading by
drag-and-drop, File > Open (Ctrl+O) or `--driver <path>`.

**Phase 2 — PE engine (done).** `core/pe` parses a driver with LIEF:
headers, sections (with entropy), imports, exports, CodeView PDB path,
header vs. computed checksum, MD5/SHA-1/SHA-256, and the embedded
Authenticode signature (signers, certificates, digest check). Loading a
driver parses it on a worker thread and shows the result on the Dashboard
(Sections / Imports / Exports / Headers / Signature tabs).

**Phase 3 — disassembly and functions (done).** `core/disasm` wraps
Capstone (x86/x64); `core/functions` finds functions by recursive-descent
disassembly seeded from the entry point, exports, the x64 exception table
(.pdata), direct call targets and code addresses loaded into registers,
and builds each function's basic blocks and call sites (with IAT calls
resolved to import names). `analysis/static/StaticAnalysisPipeline` runs
parse + discovery on a worker thread; the Functions dock lists the
functions (filterable, sortable) next to an annotated disassembly listing
(double-click a call to open the callee). Known limits are documented in
`core/functions/FunctionDiscoverer.h`: functions reachable only through
computed pointers and lacking .pdata are missed, and switch-table jumps
aren't followed.

**Phase 4 — driver model, DriverEntry and handlers (done).**
`core/driver` classifies the driver (WDM, KMDF, minifilter, NDIS,
Storport, ScsiPort, HID, AVStream) with the evidence for it, steps from the
PE entry point through argument-forwarding stubs (GsDriverEntry, KMDF's
FxDriverEntry past WdfVersionBind) to the real DriverEntry, and recovers
handler registration with a per-function value tracker over the Phase 3
disassembly:

- WDM: `DriverObject->MajorFunction[]` stores (direct, loops, `rep stos`)
  in DriverEntry and the functions it passes DriverObject to, plus
  DriverUnload, DriverStartIo and DriverExtension->AddDevice.
- KMDF: finds `WDF_BIND_INFO` (framework version, function-table
  variable), labels every call through the WDF function table using
  Microsoft's `wdffuncenum.h` (`core/driver/WdfFunctionTable.cpp`, generated
  by `scripts/python/gen_wdf_function_table.py`), and reads
  `WDF_DRIVER_CONFIG` / `WDF_IO_QUEUE_CONFIG` at `WdfDriverCreate` /
  `WdfIoQueueCreate` calls to recover EvtDriverDeviceAdd and each queue's
  EvtIo* callbacks and dispatch type.

Results are in the IRP Handlers dock; double-click a handler to open it
in Functions. Limits (flow-insensitive tracking, x64-only KMDF config
decoding, undecoded port/miniport callback structures) are listed in
`core/driver/DriverAnalyzer.h` and shown per driver where they apply.

The other docks are still empty; each is filled by the phase that
implements its view.

## Prerequisites (Windows)

- Visual Studio 2022 with "Desktop development with C++" (MSVC, plus the
  bundled CMake and Ninja)
- [vcpkg](https://github.com/microsoft/vcpkg) cloned to e.g. `C:\vcpkg`.
  Dependencies (Qt, LIEF, Capstone, spdlog, SQLite3, nlohmann-json,
  GoogleTest) come from `vcpkg.json` in manifest mode — no manual
  `vcpkg install`. The first configure builds them, which takes a while
  (Qt is the slow one); later configures reuse vcpkg's binary cache.

## Build and test

The default presets use Ninja and `cl`, so they need an x64 MSVC
environment. Run from a normal PowerShell in this directory:

```powershell
cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" && set VCPKG_ROOT=C:\vcpkg&& cmake --preset windows-msvc-debug && cmake --build --preset windows-msvc-debug && ctest --preset windows-msvc-debug'
```

- `vcvars64.bat` sets `VCPKG_ROOT` to the copy of vcpkg bundled with Visual
  Studio, so set it back to your clone afterwards, as above. (Keep
  `C:\vcpkg&&` with no space, or cmd adds a trailing space to the path.)
- The `windows-vs2022-debug` preset uses the Visual Studio generator
  instead and doesn't need vcvars, but only works when Visual Studio
  reports its installation as complete.
- If the build was configured with a different generator before, delete
  `build/` first.

The app is `build/debug/bin/dasa.exe`. Close it before rebuilding, or the
link step fails with LNK1168 (file in use).

## Tests

`dasa_core_tests` (GoogleTest):

- `core/pe` against the two synthetic drivers in `tests/fixtures/drivers/`
  (expected values taken from pefile, the parser v1 used) and against
  `C:\Windows\System32\drivers\cng.sys` as a real embedded-signed driver.
- `core/disasm` against hand-encoded instructions (expected decodes from
  the Intel SDM encodings).
- `core/functions` against the fixtures (expected functions, instruction
  and block counts derived from the generator script that wrote their
  code bytes) and against cng.sys (every export, the entry point and every
  primary .pdata entry must be found; call graph consistency).

- `core/driver` against `DASARiskyDriver.sys` (WDM) and
  `DASAKmdfSample.sys`, a synthetic KMDF driver written by
  `tests/fixtures/drivers/gen_kmdf_fixture.py` (expected entry chain, WDF
  calls, driver config and queue callbacks come from that script), and
  structurally against real WDM (beep.sys), KMDF (CAD.sys, 1394ohci.sys,
  BTHUSB.SYS) and minifilter (Wof.sys) drivers.

Tests that use files from `C:\Windows\System32\drivers` are skipped if the
file isn't present.
