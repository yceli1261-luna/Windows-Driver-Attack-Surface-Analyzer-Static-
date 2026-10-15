# DASA v2 (C++20 / Qt 6)

Native rewrite of the Driver Attack Surface Analyzer. See
`docs/DASA_V2_ARCHITECTURE.md` for the module layout and rationale, and the
product brief in the project thread for the full phase plan. The original
Python implementation lives at the repository root (`main.py`, `analysis/`,
`parser/`, etc.) and is left untouched — it's the behavioral reference this
rewrite is validated against, not code being migrated line-by-line.

## Phase 1 status

CMake project skeleton + Qt 6 application shell: dock layout (one empty
dock per WORKSPACE/RESEARCH/DYNAMIC/DATABASE/REPORTS group from the brief),
persisted window layout, dark theme, `.sys` drag-and-drop (validates and
logs the path; does not parse yet). `core`/`analysis`/`dynamic` are empty
static libraries that build and link, establishing the target graph later
phases add real sources to.

## Prerequisites (Windows)

- Visual Studio 2022 (MSVC v143 toolset, "Desktop development with C++")
- CMake >= 3.25 (bundled with VS, or standalone)
- Qt 6 (Widgets, Core, Gui) — via the Qt installer or vcpkg
- [vcpkg](https://github.com/microsoft/vcpkg), with `VCPKG_ROOT` set, for
  LIEF / Capstone / spdlog / SQLite3 / nlohmann-json / GoogleTest
  (`vcpkg.json` manifest mode — no manual `vcpkg install` needed)

If Qt isn't installed via vcpkg, point CMake at your Qt kit, e.g. add
`-DCMAKE_PREFIX_PATH=C:/Qt/6.7.2/msvc2019_64` to the configure command
below (or set it in a local `CMakeUserPresets.json`, which is gitignored).

## Build

From a **Developer PowerShell for VS 2022**, with `VCPKG_ROOT` set:

```powershell
cmake --preset windows-msvc-debug
cmake --build --preset windows-msvc-debug
```

The app binary lands at `build/debug/bin/dasa.exe`.

## Test

```powershell
ctest --preset windows-msvc-debug
```

(Currently one suite, `dasa_core_tests`, confirming `dasa_core` builds,
links, and reports the right version — the real per-module suites land
alongside their modules starting Phase 2.)

## Phase 1 verification checklist

This was scaffolded by a cloud session with file access only (no compiler,
shell, or GUI on this machine), so none of the following has been run yet.
Before calling Phase 1 done:

- [ ] `cmake --preset windows-msvc-debug` configures without error
- [ ] `cmake --build --preset windows-msvc-debug` builds `dasa_core`,
      `dasa_analysis`, `dasa_dynamic`, `dasa_app`, `dasa_core_tests`
- [ ] `ctest --preset windows-msvc-debug` passes
- [ ] `build/debug/bin/dasa.exe` launches, shows the dark-themed dock
      layout, and dragging a `.sys` file onto it updates the status bar
