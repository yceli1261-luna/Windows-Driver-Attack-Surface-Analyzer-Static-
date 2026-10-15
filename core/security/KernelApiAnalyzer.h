#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "core/driver/DriverModel.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/ioctl/IoctlExtractor.h"
#include "core/pe/PEImage.h"
#include "core/security/ApiCatalog.h"

namespace dasa::core::security {

/// One kernel API the driver uses, imported or resolved at runtime.
struct ApiUse {
    std::string name;
    std::string library;            // import DLL, or "MmGetSystemRoutineAddress" when resolved at runtime
    ApiInfo info;
    bool imported = false;
    bool resolvedAtRuntime = false; // name passed to MmGetSystemRoutineAddress
    std::vector<std::uint64_t> callers;     // functions with a call site
    std::vector<std::uint64_t> callSites;   // instruction RVAs
    std::set<std::string> reachableFrom;    // entry points that reach a caller
};

/// An instruction that only privileged code can execute and that touches
/// hardware or CPU state directly - drivers compile these from intrinsics
/// (__readmsr, __outbyte, ...), so they never show up as imports.
struct PrivilegedInstruction {
    std::uint64_t rva = 0;
    std::uint64_t function = 0;
    std::string text;               // e.g. "wrmsr", "out dx, al"
    std::string kind;               // "MSR write", "Port I/O write", ...
    ApiRisk risk = ApiRisk::High;
    std::set<std::string> reachableFrom;
};

struct KernelApiAnalysis {
    std::vector<ApiUse> apis; // sorted by risk (highest first), then name
    std::vector<PrivilegedInstruction> privileged;
    std::map<ApiCategory, int> categoryCounts;
    std::vector<std::string> entryPoints; // the roots reachability was computed from
    std::vector<std::pair<std::string, std::uint64_t>> entryPointFunctions; // same, with RVAs
    std::vector<std::string> notes;

    int countAtLeast(ApiRisk r) const;
};

/// Classifies every imported kernel API, adds names resolved at runtime via
/// MmGetSystemRoutineAddress, finds privileged instructions in the code,
/// and computes which driver entry points (DriverEntry, each IRP dispatch
/// routine, DriverUnload/AddDevice, each KMDF callback, each IOCTL handler)
/// reach every call site through the call graph.
///
/// Reachability follows direct calls and tail calls only; calls through
/// function pointers that weren't resolved are not followed, so "not
/// reachable" means "not shown reachable", not "unreachable".
KernelApiAnalysis analyzeKernelApis(const pe::PEImage& image, const functions::FunctionSet& functions,
                                    const driver::DriverAnalysis& driver, const ioctl::IoctlAnalysis& ioctls);

} // namespace dasa::core::security
