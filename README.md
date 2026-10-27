# DASA v2 (C++20 / Qt 6)

Static analysis of Windows kernel drivers: how user mode reaches a driver,
the IOCTLs and handlers it exposes, which dangerous operations are
reachable, and whether request data controls them. It opens in a Simple
mode written for non-experts; Expert mode shows the full analysis. See
`docs/DASA_V2_ARCHITECTURE.md` for the module layout and rationale. DASA v2
is a native rewrite of an earlier Python prototype, which is not part of
this repository.

## How to run DASA

DASA is a Windows desktop app that you build from source once. It only
**reads** driver files - it never loads or runs them - so it is safe to use
on your own PC.

### 1. Install the tools (once)

| What | Where to get it | Notes |
|---|---|---|
| Windows 10 or 11, 64-bit | - | About 15 GB free disk space for the first build |
| Visual Studio 2022 | [visualstudio.microsoft.com](https://visualstudio.microsoft.com/) | The free **Community** edition is fine. In the installer, tick the workload **"Desktop development with C++"**. |
| Git | [git-scm.com](https://git-scm.com/download/win) | |
| vcpkg (C++ package manager) | see below | Downloads and builds Qt and the other libraries for you |

Install vcpkg into `C:\vcpkg` - open **PowerShell** and run:

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
```

### 2. Get the DASA source

Put it in a **short folder path** such as `C:\src` - the build creates deeply
nested library folders, and Windows' 260-character path limit breaks it
under long paths (Desktop, Documents, OneDrive, ...).

```powershell
mkdir C:\src -Force
cd C:\src
git clone https://github.com/yceli1261-luna/Windows-Driver-Attack-Surface-Analyzer-Static-.git DASA
cd DASA
```

### 3. Build it

In PowerShell, inside the `DASA` folder, run this one line:

```powershell
cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" && set VCPKG_ROOT=C:\vcpkg&& cmake --preset windows-msvc-release && cmake --build --preset windows-msvc-release'
```

- **The first build takes a long time** (often 30-90 minutes): vcpkg
  downloads and compiles Qt and the other libraries. Later builds reuse
  them and take a few minutes or less.
- If you installed Visual Studio **Professional**, **Enterprise** or **Build
  Tools**, replace `Community` in the path with that edition's folder name.
- Keep `set VCPKG_ROOT=C:\vcpkg&&` exactly as written (no space before
  `&&`).

### 4. Start the app

```powershell
.\build\release\bin\dasa.exe
```

You can also double-click `dasa.exe` in `build\release\bin`, or open a
driver directly:

```powershell
.\build\release\bin\dasa.exe --driver "C:\path\to\some_driver.sys"
```

### 5. Use it

DASA opens in **Simple mode**, written for people without
reverse-engineering experience:

1. **Pick a driver.** Click **Choose a driver on this PC** (the **Drivers**
   tab lists the drivers installed on your computer; third-party ones are
   shown first) and double-click one. You can also drag a `.sys` file onto
   the window or press **Ctrl+O**.
2. **Read the verdict** on the **Overview** tab: **Safe / Worth a look /
   Risky / Dangerous**, what the driver can do, who can use it and what you
   should do. The **Problems** tab explains each problem in plain words,
   with technical details one click away.
3. **Save a report** (button on the Overview, or **File > Export HTML
   Report**, Ctrl+E) to keep it or send it to the driver's maker or your IT
   team.

**Expert mode** (button at the bottom right, **View > Expert Mode** or
**Ctrl+Shift+X**) shows the full analysis: functions and disassembly,
control-flow and call graphs, IOCTLs, devices, data flow, findings with
evidence, search, bookmarks, notes, diffing and history. **Help >
Glossary** explains the technical terms.

Every analysis is saved automatically in
`%LOCALAPPDATA%\DASA Project\DASA\dasa.db`, so earlier results, bookmarks,
notes and tags are still there next time.

### Troubleshooting

| Problem | Fix |
|---|---|
| `'cmake' is not recognized` or `cl` not found | Visual Studio's C++ workload isn't installed, or the `vcvars64.bat` path is wrong for your edition (step 3). |
| `Could not find toolchain file ... vcpkg.cmake` | vcpkg isn't at `C:\vcpkg`. Install it there (step 1) or change `C:\vcpkg` in the build line. |
| `Generator Ninja does not match the generator used previously` | Delete the `build` folder and build again. |
| `Cannot open include file: 'LIEF/...'` (or another library header) | The folder path is too long. Move or clone DASA to a short path like `C:\src\DASA`, delete the `build` folder and build again. |
| `LNK1168: cannot open dasa.exe for writing` | DASA is still running - close it, then build again. |
| The app doesn't start / "no Qt platform plugin" | Start it from `build\release\bin` (the build copies the files it needs there). |
| A driver shows "Dangerous" | Read the **Problems** tab: it says whether DASA proved that programs can control the dangerous operation or only that they can reach it. DASA can't see every safety check a driver makes - treat the verdict as a strong hint, not a final judgment. |


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

**Phase 5 — IOCTLs and device objects (done).** `core/ioctl` extracts
IOCTL codes starting from the Phase 4 handlers (WDM
`IRP_MJ_DEVICE_CONTROL` / `INTERNAL_DEVICE_CONTROL`, KMDF
`EvtIoDeviceControl` / `EvtIoInternalDeviceControl` / `EvtIoDefault`)
and the helpers they pass the request to. The request's IoControlCode is
tracked (`Irp->Tail.Overlay.CurrentStackLocation->Parameters.
DeviceIoControl.IoControlCode`, or the EvtIo callback's 5th argument),
so compares and `sub` switch chains yield exact codes; jump-table
switches are reported as ranges. IOCTL-shaped constants are used only
where the code couldn't be tracked, and labelled as such. Codes are
decoded per `CTL_CODE`. `core/driver/DeviceObjects` follows
`RtlInitUnicodeString` / static `UNICODE_STRING`s into `IoCreateDevice(Secure)`,
`IoCreateSymbolicLink`, `IoRegisterDeviceInterface` and the KMDF naming,
characteristics, symbolic-link and interface DDIs: device names, types,
`FILE_DEVICE_SECURE_OPEN`, exclusivity, SDDL, and each link paired with
the device name actually passed. Shown in the IOCTLs and Devices docks.

**Phase 6 — kernel API risk (done).** `core/security/ApiCatalog` grades
kernel APIs (critical / high / medium / info) by what they let a caller
do with arguments it controls, with a one-line reason; uncatalogued APIs
are categorised by name prefix. `core/security/KernelApiAnalyzer` adds the
call sites of every import, names resolved at runtime through
`MmGetSystemRoutineAddress`, privileged instructions compiled from
intrinsics (MSR, port I/O, control/debug registers, descriptor tables),
and which entry points (DriverEntry, IRP routines, DriverUnload /
AddDevice / StartIo, KMDF callbacks) reach each call site through the call
graph. Shown on the Dashboard's Kernel APIs tab. Risk rates the primitive,
not the driver; whether user input reaches it is for the data-flow phase.

**Phase 7 — findings and risk score (done).** `core/findings` defines a
finding as a claim plus evidence chains (user-mode name → device → entry
point → IOCTL → call path → call or instruction), with severity,
confidence, description and recommendation. `analysis/heuristics/
FindingRules` replaces v1's count-based `rules.json` with
evidence-producing rules: dangerous APIs and privileged instructions
reachable from user-request handlers (severity lowered when no
user-mode name was recovered; internal device control rated separately),
device security (FILE_DEVICE_SECURE_OPEN, default ACL with a link,
unprotected links), METHOD_NEITHER (escalated without
ProbeForRead/Write) and FILE_ANY_ACCESS IOCTLs, runtime-resolved APIs,
system callbacks, uncalled critical imports, and image hardening. The
0-100 risk score is a confidence-weighted sum with the contributing
findings listed. Shown in the Findings and Evidence docks and on the
Dashboard. Reachability is over the call graph, not data flow, and the
findings say so.

**Phase 8 — analysis database and reports (done).** Every analysis is
saved to a SQLite database (`core/database/AnalysisDatabase`) at
`%LOCALAPPDATA%\DASA Project\DASA\dasa.db`: a summary row, the findings,
IOCTLs and notable kernel APIs as rows, and the full JSON report.
`analysis/report/ReportWriter` writes the JSON report (schema
`dasa-report/1`, addresses and codes as hex strings) and a self-contained
HTML report (inline CSS, no scripts, all driver-derived text escaped). New
views: Analysis History (all stored analyses; reopen, compare two, export
a stored report, delete), Previous Findings (what changed since an earlier
analysis of the same file, matched by SHA-256 or file name), Compare
Drivers (any two analyses: findings matched on rule and title, IOCTLs on
code, APIs on name, plus the risk delta) and Export (HTML / JSON; also
File > Export, Ctrl+E / Ctrl+Shift+E). Re-analyzing a file adds a new
entry rather than replacing the old one.

**Phase 9 — call graph and control flow (done).** `core/cfg/GraphLayout`
is a layered graph layout (back edges reversed, longest-path layers,
barycenter crossing reduction, edges routed through every layer they
cross, loops routed up the right side). `core/cfg/ControlFlowGraph`
classifies each block edge as taken / not taken / jump and each exit as
return, trap, tail call, call that doesn't return, or an indirect jump
whose targets weren't followed. `core/callgraph/CallGraph` holds the
direct calls between functions and to imports (with call-site counts and
tail calls), marks entry-point roles (DriverEntry, IRP handlers, KMDF
callbacks) and call cycles, and extracts a function's neighbourhood
(callers / callees to a depth, imports of the focused function or of
everything shown). The Control Flow view draws a function's blocks with
annotated calls and follows the selection in Functions; the Call Graph
view shows the neighbourhood with risky imports coloured, and
double-clicking navigates both. Functions over 700 blocks aren't drawn.
Calls through pointers (callbacks, the WDF function table) aren't call
graph edges.

**Phase 10 — data flow (done).** `core/dataflow/TaintAnalyzer` follows
request data from the user-request handlers (IRP_MJ_DEVICE_CONTROL /
INTERNAL_DEVICE_CONTROL / WRITE, KMDF EvtIoDeviceControl /
EvtIoInternalDeviceControl / EvtIoWrite) through registers, stack slots
and direct calls (arguments in, return values out) over each function's
control-flow graph, to sensitive API arguments (MmMapIoSpace, memcpy,
ExFreePool, PsLookupProcessByProcessId, ...), privileged instructions
(wrmsr, rdmsr, in/out, mov crN) and memory accesses through
request-chosen addresses or unprobed user pointers. Sources are the
SystemBuffer contents, buffer lengths, Type3InputBuffer, Irp->UserBuffer
and the KMDF EvtIo* lengths / WdfRequestRetrieve*Buffer outputs;
ProbeForRead/Write and inline `MmUserProbeAddress` checks count as probes.
Each flow names where every value was read and which IOCTL's case leads
to it. New findings DASA-TAINT-API / -INSTRUCTION / -WRITE / -READ and
DASA-UNPROBED-USER-POINTER; DASA-REACH-* now note when a call's arguments
are constants. Shown in the Data Flow dock and the reports.

Limits: x64 only; paths are merged rather than tracked separately; range
checks aren't recognised (a flow means "can reach"); heap/global memory,
indirect calls and switch-table cases aren't followed; for IRP_MJ_WRITE
only the length is traced; handlers that read Irp->RequestorMode get
their flows lowered because they may accept such data only from kernel
callers. On large Microsoft drivers the results are still noisy - it is
tuned for small third-party drivers.

**Phase 11 — research tools (done).** The research column now works:
Search (Ctrl+F) looks through functions, imports, exports, strings
(ASCII and UTF-16 in data sections, with the function that uses them),
instructions, IOCTLs, devices and findings by substring or regular
expression (`analysis/search/Search`); Bookmarks keep labelled, annotated
addresses; Notes is a free-text notebook saved as you type; Tags label
drivers and list every driver with a tag; and the Investigation Workspace
lists all drivers you have annotated with their latest risk. Bookmarks,
notes and tags are stored in the analysis database per file SHA-256, so
they follow the exact file across re-analysis and renamed copies.

**Phase 12 — remaining static views (done).** Drivers lists the drivers
loaded right now (from the Service Control Manager and the kernel module
list), in System32\drivers or in any folder, with company, description and
version, third-party only by default, marking ones already analysed;
double-click analyses one. Current Analysis shows what each stage produced
and the limits that applied. Diff compares the loaded driver with another
file (`analysis/diff/AnalysisDiff`): functions matched by an
address-independent instruction fingerprint, then name, then called
imports and size, reported as changed / added / removed / identical
(changed functions that call risky APIs first - where a security fix
usually is), plus import, export, section, IOCTL, device and finding
deltas. Security Assessment (`analysis/report/Assessment`) writes a
plain-language verdict, how user mode reaches the driver, the top risks,
protections present and missing, next steps and coverage limits.

**Phase 13 — Simple mode (done).** DASA starts in Simple mode, written for
people without reverse-engineering knowledge: an Overview with a
traffic-light verdict (Safe / Worth a look / Risky / Dangerous), the maker
and version of the file, and plain answers to "What can this driver do?",
"Who can use it?" and "What should I do?"; a Problems list with every
finding in plain words and its technical details one click away; and the
Drivers list, which scans the PC as soon as it is opened. The wording
comes from fixed templates per finding rule and capability category
(`analysis/report/PlainLanguage`), so it says no more than the evidence.
Expert mode (button in the status bar, View > Expert Mode, Ctrl+Shift+X)
shows every view; Help > Glossary explains the technical terms.

Dynamic analysis (loading the driver in a VM under Driver Verifier and
WinDbg) is out of scope: DASA is a static analyzer, safe to run on the
analyst's own machine.

## Developer build (Debug and tests)

For working on DASA itself, build the Debug configuration and run the test
suite (same tools as above):

```powershell
cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" && set VCPKG_ROOT=C:\vcpkg&& cmake --preset windows-msvc-debug && cmake --build --preset windows-msvc-debug && ctest --preset windows-msvc-debug'
```

The Debug app is `build\debug\bin\dasa.exe`. Notes:

- `vcvars64.bat` points `VCPKG_ROOT` at the copy of vcpkg bundled with
  Visual Studio, which is why the line sets it back to `C:\vcpkg`.
- The `windows-vs2022-debug` preset uses the Visual Studio generator instead
  and doesn't need vcvars, but only works when Visual Studio reports its
  installation as complete.

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

- IOCTL and device recovery against `DASAWdmSample.sys`, written by
  `tests/fixtures/drivers/gen_wdm_fixture.py` (tracked sub-chain codes, a
  code passed to a helper, a jump-table range, a buffer-length decoy that
  must not be reported, a named device with its symbolic link), the
  KMDF fixture (EvtIoDeviceControl compares, WDF device name, link,
  characteristics, interface), the 24 codes of `DASARiskyDriver.sys`, and
  real beep.sys (IOCTL_BEEP_SET, `\Device\Beep`) and null.sys (no IOCTL
  handler, `\Device\Null`).

- Kernel API classification and reachability against `DASAWdmSample.sys`
  (MmMapIoSpace, `wrmsr` and `in` only reachable from
  IRP_MJ_DEVICE_CONTROL; ZwQuerySystemInformation resolved at runtime from
  DriverEntry) and the risky fixture's imports.

- Findings over the full pipeline for all three fixtures (e.g. the WDM
  fixture's MmMapIoSpace chain `\DosDevices\DasaWdm` →
  IRP_MJ_DEVICE_CONTROL → IOCTL 0x0022E00B → sub_1300 → call at 0x1320)
  and the risk-score weights.

- The analysis database on a temporary file (round trip of hand-written
  analyses, history matching, delete cascading to child rows checked with
  SQLite directly, comparison) and the reports for `DASAWdmSample.sys`
  (the JSON's codes, device, link and MmMapIoSpace reachability match the
  generator; the HTML is escaped and script-free).

- Graph layout on small hand-built graphs (layers, no overlaps, edge
  endpoints, back edges and self loops, long edges bending through each
  layer), control-flow graphs of the WDM fixture's helper and
  IRP_MJ_DEVICE_CONTROL routine (blocks, taken/not-taken edges, the
  unresolved switch jump), and its call graph (DeviceControl → helper →
  MmMapIoSpace, three RtlInitUnicodeString call sites, entry-point roles,
  neighbourhoods, recursion on a hand-built cycle).

- Data flow against `DASATaintSample.sys`, written by
  `tests/fixtures/drivers/gen_taint_fixture.py` (instructions checked with
  Python's capstone): request data into MmMapIoSpace through a helper,
  memcpy destination and length, wrmsr operands, a write-what-where, an
  unprobed METHOD_NEITHER read, and a probed one that must not be
  reported - with the exact source of each value and the IOCTL whose case
  leads there; the resulting findings; and the WDM fixture's
  MmMapIoSpace call, whose constant arguments must not be a flow.

- Search over the WDM fixture (its UTF-16 strings at the RVAs the
  generator placed them, the functions that load them, imports, `wrmsr`,
  IOCTLs, regex, case and limit handling) and bookmarks / notes / tags in
  a temporary database.

- Diff of the WDM and taint fixtures (import, device and IOCTL deltas from
  the two generators; CreateClose matched across addresses by its
  fingerprint; a file against itself is all identical) and the security
  assessment of both fixtures.

- Simple-mode wording for both fixtures and a quiet real driver (verdicts,
  capabilities, who can use it, one problem per finding without
  reverse-engineering jargon in the headlines).

The fixture generators share `tests/fixtures/drivers/_pe_writer.py`. Tests
that use files from `C:\Windows\System32\drivers` are skipped if the file
isn't present.
