#pragma once

#include <string>
#include <string_view>

namespace dasa::core::security {

enum class ApiCategory {
    PhysicalMemory,  // physical address space, I/O space, sections over physical memory
    VirtualMemory,   // mapping, copying, MDLs, other processes' memory
    Pool,            // kernel heap
    Process,         // process/thread objects, attach, terminate
    Token,           // tokens, privileges, impersonation
    Callbacks,       // system-wide notification and filtering callbacks
    Registry,
    FileSystem,
    ObjectManager,
    Hardware,        // HAL bus/port access
    DriverLoading,
    DynamicResolution,
    Validation,      // ProbeForRead/Write and similar checks on user input
    Device,          // device objects, links, interfaces
    Irp,             // IRP handling and forwarding
    Synchronization,
    Framework,       // KMDF / WDF loader
    FilterManager,
    Networking,
    Runtime,         // Rtl* helpers
    Other,
};

/// How much an API can do on behalf of a caller if its arguments come from
/// user mode. This rates the primitive, not the driver: whether the call is
/// actually reachable with attacker-controlled input is decided later
/// (reachability here, data flow in a later phase).
enum class ApiRisk {
    Info,     // routine
    Medium,   // useful to an attacker in combination
    High,     // dangerous capability (arbitrary process/handle/token/callback)
    Critical, // read/write primitive over memory or hardware
};

struct ApiInfo {
    ApiCategory category = ApiCategory::Other;
    ApiRisk risk = ApiRisk::Info;
    std::string why;        // empty for routine APIs
    bool catalogued = false; // false = categorised only by name prefix
};

/// Classification for a kernel export by name (e.g. "MmMapIoSpace").
ApiInfo classifyApi(std::string_view name);

const char* categoryName(ApiCategory c);
const char* riskName(ApiRisk r);

} // namespace dasa::core::security
