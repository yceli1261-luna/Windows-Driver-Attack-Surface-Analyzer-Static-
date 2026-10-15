# DASA v2 — C++20 / Qt 6 Architecture Proposal

This proposes the module layout and build structure for rebuilding DASA as a
native Windows application. It covers: what the current Python code does,
what is worth carrying forward, where it is limited, and the C++/Qt module
layout + CMake skeleton to replace it. No analysis/finding logic is written
yet — this is the structural plan to agree on before Phase 1 code lands.

## 1. What the existing Python implementation does

Pipeline, driven by `main.py::analyze_driver`:

```
PEParser.parse()               -> PEParseResult (pefile-backed: headers,
                                    sections, imports, exports, signature,
                                    hashes)
ImportAnalyzer.analyze()       -> KernelAPIAnalysis (categorizes imports
                                    against a static table, flags "sensitive"
                                    APIs, detects WDF via import-name markers)
DriverEntryAnalyzer.analyze()  -> disassembles DriverEntry (Capstone),
                                    detects DriverObject->MajorFunction[]
                                    writes via a register-taint mini-tracker,
                                    finds DriverUnload/AddDevice, collects
                                    referenced symbol name strings
DispatchTableAnalyzer.analyze()-> normalizes DriverEntry's findings into the
                                    28 IRP_MJ_* slots, flags key dispatches,
                                    extracts the IRP_MJ_DEVICE_CONTROL /
                                    INTERNAL_DEVICE_CONTROL handler address
IOCTLAnalyzer.analyze()        -> three-tier IOCTL extraction (see below)
DeviceObjectAnalyzer.analyze() -> raw ASCII/UTF-16 string scan for
                                    \Device\... and \DosDevices\...\??\...
                                    names, pairs links to devices by suffix
                                    match
GhidraAnalyzer.analyze()       -> optional: shells out to analyzeHeadless
                                    with a bundled Jython post-script,
                                    parses its JSON, results get merged
                                    (additively, keyed by code/name) into
                                    the above four
AttackSurfaceGraph.build_and_export() -> builds a networkx DiGraph
                                    (driver/device/symlink/IRP/IOCTL/API
                                    nodes), renders via Graphviz to
                                    PNG+DOT+GraphML
RiskScorer.score()             -> evaluates risk/rules.json rule set against
                                    the above, produces a RiskScore
                                    (level/percent/hits) + MetricsSnapshot
DriverDatabase                 -> SQLite persistence (drivers, imports,
                                    ioctls, device_objects, symbolic_links,
                                    dispatch_entries, risk_scores, analyses)
HTMLReportGenerator             -> Jinja2 HTML + JSON report
```

`gui.py` is a Tkinter-ish wrapper that drives `run_analysis_pipeline()` on a
background thread and shows the resulting HTML in an embedded view — it is
not a real workspace UI, just a progress dialog in front of the CLI path.

### IOCTL extraction — the one genuinely good piece of design

`IOCTLAnalyzer.analyze()` (`analysis/ioctl.py`) is tiered, and the tiering is
worth preserving as a concept:

1. **Anchored disassembly scan** — if a WDM `IRP_MJ_DEVICE_CONTROL` /
   `INTERNAL_DEVICE_CONTROL` handler address was recovered from the dispatch
   table, disassemble a window from it and pull `cmp`/`test` immediates
   against `[...]`/`ptr` operands that pass `_looks_like_ioctl()`.
2. **WDF/full-text fallback** (`_scan_text_sections_for_ioctls`) — if no
   handler address exists, or too few hits came back, disassemble *every*
   executable section and apply the same cmp/test pattern, then run
   `_filter_text_scan_noise()`: keep only device-type codes that (a) are
   among the top-3 most frequent device types in the binary and (b) occur
   at least twice. This existence of a confidence filter for the
   unanchored case is the right idea — it is explicitly there because an
   unconstrained whole-.text scan is noisy.
3. **Section data scan** (`_heuristic_scan_section_for_ioctls`) — last
   resort, scans `.data`/`.rdata` for 32-bit values that look like IOCTL
   codes, only if the disassembly tiers came up short.

`decode_ioctl()` correctly implements the real `CTL_CODE` bit layout
(device type / function / method / access) rather than guessing.

### Where the current design is limited

1. **KMDF handling is a text-scan fallback, not a model.** `is_wdf_driver()`
   (`analysis/imports.py`) only checks for `Wdf*` import names. Once a
   driver is flagged WDF, the *only* adaptation is
   `_scan_text_sections_for_ioctls()` — disassemble everything, pattern-match
   cmp/test against IOCTL-shaped immediates, denoise by frequency. There is
   no actual understanding of:
   - `WDFDEVICE_INIT` / `WdfDeviceCreate` and the resulting `WDFDEVICE`
     handle's callback table (`WDF_PNPPOWER_EVENT_CALLBACKS`,
     `WDF_OBJECT_ATTRIBUTES`, context size/type via `WdfObjectGetTypedContext`)
   - `WdfIoQueueCreate` + `WDF_IO_QUEUE_CONFIG` (queue dispatch type —
     sequential/parallel/manual — and which `EvtIo*` callbacks are wired:
     `EvtIoDeviceControl`, `EvtIoInternalDeviceControl`, `EvtIoRead`,
     `EvtIoWrite`, `EvtIoStop`, `EvtIoResume`), so there's no way to tell
     *which* queue (there can be several, with different dispatch
     semantics and different IOCTL sets) an extracted IOCTL belongs to
   - `WdfRequestRetrieveInputBuffer`/`OutputBuffer`/`InputMemory` etc. to
     recover each handler's actual buffer-access method, instead of
     inferring METHOD_* purely from the IOCTL code's own low bits (which is
     correct per CTL_CODE semantics, but doesn't cross-check against how
     the handler actually calls Wdf buffer-retrieval APIs — the thing a
     reviewer would actually want to look at for e.g. a METHOD_NEITHER
     handler that calls `WdfRequestRetrieveUnsafeUserInputBuffer` directly)
   - `WDF_DEVICE_IO_TYPE` / preferred node feature flags that affect which
     buffer path is live
   - KMDF version resolution (`WdfVersionBind`) and the fact that WDF
     entry points are themselves indirected through a function-table
     structure (`WDFFUNCTIONS`) rather than being plain imports — so "is
     this a sensitive API" can't be answered by import-name matching alone
     once a call goes through `WdfDeviceCreate`-style indirection
   The result: for a KMDF driver, DASA today can tell you IOCTL codes
   exist and roughly where, but not which queue/callback owns which code,
   what each callback's declared buffer-access method actually is from the
   framework's point of view, or anything about PNP/power callbacks,
   preprocessed-buffer settings, or per-queue power-managed state — all of
   which matter for attack-surface reasoning on a modern driver, since
   almost everything shipped today is KMDF, not raw WDM.

2. **DriverEntry analysis is a single linear disassembly pass with ad hoc
   register tracking.** `_detect_major_function_write` tracks `mov`/`lea`
   register values in a flat dict with no basic-block/branch awareness —
   it does not follow calls (so a driver that assigns `MajorFunction[]`
   inside a helper called from DriverEntry is invisible), and it stops
   after `heuristic_extend_size` (0x2000) bytes with no explicit
   function-end detection (relies on the byte window happening to be big
   enough).

3. **No function discovery, call graph, or control-flow graph at all.**
   Everything downstream (IOCTL extraction, device/symlink scanning) acts
   on byte offsets and raw disassembly windows, not functions. There's no
   way to ask "who calls this handler," "what does this handler call," or
   render a CFG — which the brief lists as a major feature.

4. **No data-flow analysis.** Nothing traces a value from
   `Irp->AssociatedIrp.SystemBuffer` / the IOCTL's input buffer through to
   a sensitive call. METHOD_NEITHER + FILE_ANY_ACCESS flags from
   `decode_ioctl()` are a proxy heuristic, not evidence of an actual
   reachable dangerous operation.

5. **Findings are pure rule hits, not evidence objects.** `risk/rules.py` +
   `risk/scorer.py` (not fully reproduced here, scope deferred per this
   turn's instructions) produce a flat score from `rules.json` conditions
   — there's no per-finding evidence chain (entry point → IOCTL → function
   → dataflow → sensitive op) of the kind the product brief wants.

6. **Device/symlink matching is string-proximity, not control-flow.**
   `create_device_objects_from_strings()` pairs a symlink to a device by
   *name suffix match* across all strings found anywhere in the binary —
   no verification that `IoCreateSymbolicLink` and `IoCreateDevice` were
   actually called with those exact strings, or that they're related in
   code.

7. **Ghidra integration is fire-and-forget batch, not a merge-aware
   backend.** It writes a temp Jython script, shells out to
   `analyzeHeadless -noanalysis` (so Ghidra does *no* auto-analysis before
   running the script — likely means Ghidra's own function/xref discovery
   isn't even active), and the merge functions in `main.py`
   (`_merge_ghidra_*`) do simple key-based union, no provenance tracking of
   which fields came from where for display purposes.

8. **One-shot, blocking, process-per-run.** No incrementality: every run
   re-parses, re-disassembles, and re-scores from scratch; there's no
   persisted function/CFG model to reuse across a Ghidra pass and future
   investigation.

### Worth carrying forward (as behavior, not code)
- PE metadata extraction field list (headers, sections w/ characteristics
  flags, imports/exports, DOS stub, signature presence) — comprehensive
  enough to reuse as the spec for the new PE module.
- SHA256/SHA1/MD5 hashing on load.
- The `CTL_CODE` decode table and device-type name table.
- The three-tier IOCTL extraction *strategy* (anchored scan → fallback
  full-text scan → noise filter by device-type frequency → last-resort
  section scan) as a strategy, reimplemented on top of real function
  discovery instead of raw byte windows.
- The IRP_MJ_* dispatch-table concept (28 well-known slots, "key dispatch"
  subset) for the WDM case.
- Risk-rule JSON (`risk/rules.json`) as a reference list of conditions to
  re-derive from, not to load the same engine, once the finding model
  exists.
- SQLite schema shape (drivers / imports / ioctls / devices / symlinks /
  dispatch / risk_scores / analyses) as a starting point for the new
  schema, extended with functions/CFG/findings/evidence/notes tables.
- Ghidra-headless-with-postscript as the integration mechanism, but with
  real analysis enabled and a typed result schema instead of ad hoc JSON.

## 2. Proposed C++20 / Qt 6 module layout

```
DASA/
  CMakeLists.txt
  cmake/
    FindLIEF.cmake, FindCapstone.cmake, ... (or vcpkg/Conan manifests)

  app/                      # Qt application shell
    main.cpp
    MainWindow.{h,cpp}       # QMainWindow, dock layout host
    DockManager.{h,cpp}      # persisted QMainWindow::save/restoreState layout
    CommandPalette.{h,cpp}   # Ctrl+P
    JobManager.{h,cpp}       # QThreadPool-backed background job queue,
                              # progress/toast signals into the GUI
    ThemeManager.{h,cpp}     # dark theme QPalette/QSS
    RecentFilesModel.{h,cpp}

  core/                     # Pure analysis engine, no Qt dependency —
                              # a static/shared lib the GUI and a future
                              # CLI both link against.
    pe/
      PEImage.h               # parsed-PE value type (LIEF-backed)
      PEParser.{h,cpp}        # wraps LIEF::PE, hashing, signature parse
    disasm/
      Disassembler.{h,cpp}    # Capstone wrapper, arch-agnostic
      Instruction.h
    functions/
      FunctionDiscoverer.{h,cpp}  # entry-point + call-target + export-
                                    # seeded function discovery
      Function.h                  # function value type: range, basic
                                    # blocks, calls, call sites
    cfg/
      BasicBlock.h
      CfgBuilder.{h,cpp}
    callgraph/
      CallGraphBuilder.{h,cpp}
    driver/
      DriverModel.h            # WDM | KMDF | UMDF | Unknown + confidence
      DriverModelDetector.{h,cpp}
      WdmDispatchAnalyzer.{h,cpp}   # MajorFunction[] recovery, now on top
                                      # of real functions/CFG (follows
                                      # calls, not just a flat window)
      WdfAnalyzer.{h,cpp}            # WdfDeviceCreate / WdfIoQueueCreate /
                                      # WDF_IO_QUEUE_CONFIG / EvtIo* callback
                                      # recovery — the KMDF model gap in v1
      WdfFunctionTable.h              # models the WDFFUNCTIONS indirection
    ioctl/
      IoctlCodec.h              # CTL_CODE decode/encode (ports v1 tables)
      IoctlExtractor.{h,cpp}    # anchored scan / WDF queue-aware scan /
                                  # fallback text scan, built on Function
                                  # and WdfAnalyzer output instead of raw
                                  # byte windows
    dataflow/
      ValueSource.h             # tainted-origin kinds: IOCTL input buffer,
                                  # input size, user pointer, etc.
      DataflowTracer.{h,cpp}    # intra/inter-procedural def-use tracking,
                                  # explicit confidence + "could not
                                  # establish" result states
    security/
      SensitiveApiCatalog.h     # ports KERNEL_API_CATEGORIES / 
                                  # SENSITIVE_KERNEL_APIS tables
      HeuristicRule.h           # typed rule interface (condition + 
                                  # evidence-producing, not just a score)
    findings/
      Finding.h                  # id/title/severity/confidence/category/
                                  # evidence chain — the v1 gap
      Evidence.h
    database/
      Database.{h,cpp}           # SQLite wrapper (schema in 
                                  # database/schema.sql)
      Repositories/*.{h,cpp}     # one repo class per entity

  analysis/
    static/
      StaticAnalysisPipeline.{h,cpp}  # orchestrates core/* in the order
                                        # from the product brief
    heuristics/
      (concrete HeuristicRule implementations)
    ghidra/
      GhidraHeadlessRunner.{h,cpp}    # process launch, typed result
      GhidraResultMerger.{h,cpp}      # provenance-tagged merge into
                                        # core/ models
    signatures/
      (future: known-good/known-bad signature matching)

  dynamic/
    windbg/
      WinDbgSession.{h,cpp}     # DbgEng COM wrapper
    verifier/
      DriverVerifierController.{h,cpp}
    vm/
      HyperVController.{h,cpp}  # snapshot/start/stop via WMI/PowerShell
    etw/
      EtwSession.{h,cpp}

  ui/                          # Qt widgets/models, one subdir per
                                 # workspace view from the brief; each
                                 # talks to core/ through Qt item models,
                                 # never touches analysis internals
    dashboard/
    driver_view/
    function_view/               # includes the assembly view widget
    ioctl_view/
    graph_view/                  # QGraphicsView-based, fed by
                                   # callgraph/ioctl graph data, not a
                                   # decorative layout
    findings_view/
    report_view/

  scripts/
    python/                      # automation/export helpers only —
                                   # never required at analysis time

  tests/
    core/                        # GoogleTest, one suite per core/ module
    fixtures/                    # synthetic test driver corpus (built
                                   # from tiny WDM/KMDF sample sources,
                                   # not just the Python-era samples/)

  resources/
    icons/, qss/, fonts/
```

### Library boundaries (why this shape)
- `core` has **no Qt dependency** — it is a static library so the analysis
  engine is independently testable (GoogleTest links it directly) and so a
  future headless CLI can reuse it without pulling in Qt.
- `analysis` depends on `core` but not on `ui`/`app` — it's where
  heuristics and the Ghidra backend live, since they're orchestration over
  `core` primitives rather than primitives themselves.
- `dynamic` depends on `core` (to feed WinDbg/ETW evidence back into
  `findings`/`database`) but is otherwise isolated — it's the only module
  that touches an external VM/debugger process, so it's easiest to stub out
  in tests independently.
- `ui` depends on `core`+`analysis`+`dynamic` read-only through Qt item
  models; it never reimplements analysis logic itself (the v1 Tkinter GUI
  mistake, where `gui.py` and `main.py` both existed as separate paths, is
  avoided by having exactly one pipeline entry point in `analysis/static/`
  that both a future CLI and `app/` call).
- `app` is the executable: window chrome, docking, job scheduling, theming.
  Analysis never runs on the Qt GUI thread — `JobManager` pushes work onto
  `QThreadPool`/worker `QThread`s and results come back via queued
  signal/slot connections, which is how "GUI must never freeze" gets
  enforced structurally rather than by convention.

### Key new concepts vs. v1 (structural only, no detection logic yet)
- `Function` / `CfgBuilder` / `CallGraphBuilder` give every later stage
  (IOCTL extraction, dataflow, findings) a real unit to attach evidence to,
  instead of raw addresses.
- `DriverModelDetector` + `WdfAnalyzer` replace the single
  `is_wdf_driver()` boolean with an actual KMDF object model (queues,
  callbacks, buffer-access method per callback) — this directly targets
  the KMDF limitation called out in the brief.
- `findings/Finding.h` + `Evidence.h` exist as a module from day one, even
  though no concrete findings are implemented until Phase 7, so nothing
  later has to retrofit an evidence chain onto score-only output the way
  v1's `risk/rules.py` would need to be.

## 3. CMake / Phase 1 shell

Top-level `CMakeLists.txt` responsibilities: C++20, MSVC toolchain, Qt6
(Widgets + maybe Qt6::Charts for later), subdirectories for `core`,
`analysis`, `dynamic`, `app`, `tests`; `BUILD_TESTING` option wired to
GoogleTest via `enable_testing()`/`add_test()`; dependency acquisition via
vcpkg manifest mode (`vcpkg.json` pinning LIEF, Capstone, spdlog, SQLite3,
nlohmann-json, GoogleTest) so a `cmake --preset` + `cmake --build` from a
Developer PowerShell is the whole build story — no bespoke fetch scripts.

Phase 1 deliverable is intentionally small: the CMake tree above with empty
`core`/`analysis`/`dynamic` libraries (each building and linking, no logic
yet) and a Qt 6 `app/MainWindow` shell with the dock layout skeleton (empty
dock widgets titled per the brief's WORKSPACE/RESEARCH/DYNAMIC/DATABASE/
REPORTS nav groups), drag-and-drop `.sys` acceptance that just logs the
dropped path via spdlog, and the dark theme applied. No PE parsing, no
disassembly yet — that's Phase 2.

**Build/verification note:** this session has file access to the project
folder but not a compiler, shell, or the ability to launch a GUI on your
machine. I can write the CMake tree and shell code, but I cannot compile,
run tests, or confirm the window actually opens. Phase 1's gate ("compile,
run tests, launch GUI, verify, fix errors") needs to happen on your side —
on the device itself via Remote Control, or by you running
`cmake --preset ... && cmake --build ...` locally — before we call Phase 1
done.

## 4. Proposed next steps
1. You confirm/adjust this module layout and the vcpkg dependency list.
2. I create the directory tree above, the CMake files, `vcpkg.json`, and the
   Qt shell (`MainWindow` + dock skeleton + theme + drag-and-drop stub),
   alongside the existing Python code (nothing in the current tree is
   touched or deleted).
3. You build it (or I drive a Remote Control session on your machine) to
   confirm Phase 1's compile+launch gate before Phase 2 (PE engine) starts.
