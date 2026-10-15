#include "core/security/ApiCatalog.h"

#include <array>

namespace dasa::core::security {

namespace {

using C = ApiCategory;
using R = ApiRisk;

struct Entry {
    std::string_view name;
    ApiCategory category;
    ApiRisk risk;
    std::string_view why;
};

// Rated by what the API lets a caller do with arguments it controls.
// Sources: WDK documentation of each routine and the vulnerable-driver
// classes these primitives are known for (physical memory R/W, process
// memory R/W, arbitrary handle/token operations, MSR/port access).
constexpr Entry kCatalog[] = {
    // Physical memory and I/O space
    {"MmMapIoSpace", C::PhysicalMemory, R::Critical, "Maps a physical address range into kernel virtual memory"},
    {"MmMapIoSpaceEx", C::PhysicalMemory, R::Critical, "Maps a physical address range into kernel virtual memory"},
    {"MmUnmapIoSpace", C::PhysicalMemory, R::Medium, "Unmaps memory mapped with MmMapIoSpace"},
    {"MmCopyMemory", C::PhysicalMemory, R::Critical, "Copies from a physical or virtual address the caller chooses"},
    {"MmGetPhysicalAddress", C::PhysicalMemory, R::High, "Translates kernel virtual addresses to physical ones (address disclosure)"},
    {"MmGetVirtualForPhysical", C::PhysicalMemory, R::High, "Translates a physical address to a kernel virtual address"},
    {"MmMapMemoryDumpMdl", C::PhysicalMemory, R::High, "Maps physical pages described by an MDL"},
    {"ZwOpenSection", C::PhysicalMemory, R::High, "Opens a section object - with \\Device\\PhysicalMemory this exposes all of RAM"},
    {"ZwMapViewOfSection", C::PhysicalMemory, R::Critical, "Maps a section (e.g. \\Device\\PhysicalMemory) into a process"},
    {"NtMapViewOfSection", C::PhysicalMemory, R::Critical, "Maps a section into a process"},
    {"ZwUnmapViewOfSection", C::VirtualMemory, R::Medium, "Unmaps a view from a process"},
    {"MmAllocateContiguousMemorySpecifyCache", C::PhysicalMemory, R::Medium, "Allocates physically contiguous memory"},
    {"MmMapLockedPages", C::VirtualMemory, R::High, "Maps MDL-described pages; with a user-supplied MDL, maps arbitrary pages"},
    {"MmMapLockedPagesSpecifyCache", C::VirtualMemory, R::High, "Maps MDL-described pages, possibly into user mode"},
    {"MmMapLockedPagesSpecifyCacheEx", C::VirtualMemory, R::High, "Maps MDL-described pages, possibly into user mode"},
    {"MmBuildMdlForNonPagedPool", C::VirtualMemory, R::Medium, "Builds an MDL over nonpaged memory"},
    {"IoAllocateMdl", C::VirtualMemory, R::Medium, "Describes a buffer (often a user buffer) for mapping"},
    {"MmProbeAndLockPages", C::VirtualMemory, R::Medium, "Locks a buffer's pages; checks access for UserMode callers"},
    {"MmSecureVirtualMemory", C::VirtualMemory, R::Info, ""},
    // Other processes' memory and process control
    {"MmCopyVirtualMemory", C::VirtualMemory, R::Critical, "Copies memory between two processes"},
    {"ZwReadVirtualMemory", C::VirtualMemory, R::Critical, "Reads another process's memory"},
    {"ZwWriteVirtualMemory", C::VirtualMemory, R::Critical, "Writes another process's memory"},
    {"NtReadVirtualMemory", C::VirtualMemory, R::Critical, "Reads another process's memory"},
    {"NtWriteVirtualMemory", C::VirtualMemory, R::Critical, "Writes another process's memory"},
    {"ZwAllocateVirtualMemory", C::VirtualMemory, R::High, "Allocates memory, possibly in another process"},
    {"NtAllocateVirtualMemory", C::VirtualMemory, R::High, "Allocates memory, possibly in another process"},
    {"ZwProtectVirtualMemory", C::VirtualMemory, R::High, "Changes page protection, possibly in another process"},
    {"NtProtectVirtualMemory", C::VirtualMemory, R::High, "Changes page protection, possibly in another process"},
    {"ZwFreeVirtualMemory", C::VirtualMemory, R::Medium, "Frees memory, possibly in another process"},
    {"KeStackAttachProcess", C::Process, R::High, "Switches to another process's address space"},
    {"KeAttachProcess", C::Process, R::High, "Switches to another process's address space"},
    {"KeUnstackDetachProcess", C::Process, R::Info, ""},
    {"PsLookupProcessByProcessId", C::Process, R::High, "Gets a process object from a caller-supplied PID"},
    {"PsLookupThreadByThreadId", C::Process, R::High, "Gets a thread object from a caller-supplied TID"},
    {"ZwOpenProcess", C::Process, R::High, "Opens a kernel handle to any process (no access check for kernel handles)"},
    {"NtOpenProcess", C::Process, R::High, "Opens a handle to any process"},
    {"ZwOpenThread", C::Process, R::High, "Opens a handle to any thread"},
    {"ObOpenObjectByPointer", C::ObjectManager, R::High, "Creates a handle to an object; with KernelMode access checks are skipped"},
    {"ZwTerminateProcess", C::Process, R::High, "Terminates a process (e.g. security software)"},
    {"NtTerminateProcess", C::Process, R::High, "Terminates a process"},
    {"PsTerminateSystemThread", C::Process, R::Info, ""},
    {"ZwSuspendProcess", C::Process, R::High, "Suspends a process"},
    {"ZwSetInformationProcess", C::Process, R::High, "Changes process properties (protection, token, ...)"},
    {"ZwSetInformationThread", C::Process, R::Medium, "Changes thread properties (e.g. hides from debugger)"},
    {"PsSetContextThread", C::Process, R::High, "Changes another thread's register context"},
    {"KeInitializeApc", C::Process, R::High, "Prepares an APC - used to inject code into threads"},
    {"KeInsertQueueApc", C::Process, R::High, "Queues an APC to a thread"},
    {"PsCreateSystemThread", C::Process, R::Medium, "Starts a kernel thread"},
    {"PsGetProcessPeb", C::Process, R::Medium, "Reads another process's PEB"},
    // Tokens and privileges
    {"ZwOpenProcessToken", C::Token, R::High, "Opens another process's token"},
    {"ZwOpenProcessTokenEx", C::Token, R::High, "Opens another process's token"},
    {"PsReferencePrimaryToken", C::Token, R::High, "Gets a process's primary token (token stealing)"},
    {"ZwDuplicateToken", C::Token, R::High, "Duplicates a token"},
    {"ZwAdjustPrivilegesToken", C::Token, R::High, "Enables or disables token privileges"},
    {"ZwSetInformationToken", C::Token, R::High, "Changes token properties"},
    {"PsImpersonateClient", C::Token, R::Medium, "Impersonates a client's security context"},
    {"SeSinglePrivilegeCheck", C::Validation, R::Info, "Checks the caller holds a privilege (a mitigation)"},
    {"SeAccessCheck", C::Validation, R::Info, "Performs an access check (a mitigation)"},
    {"SeAssignSecurity", C::Token, R::Medium, "Builds a security descriptor for a new object"},
    // System-wide callbacks
    {"ObRegisterCallbacks", C::Callbacks, R::High, "Intercepts process/thread handle creation system-wide"},
    {"PsSetCreateProcessNotifyRoutine", C::Callbacks, R::High, "Notified of every process creation"},
    {"PsSetCreateProcessNotifyRoutineEx", C::Callbacks, R::High, "Notified of, and can block, every process creation"},
    {"PsSetCreateProcessNotifyRoutineEx2", C::Callbacks, R::High, "Notified of, and can block, every process creation"},
    {"PsSetCreateThreadNotifyRoutine", C::Callbacks, R::High, "Notified of every thread creation"},
    {"PsSetLoadImageNotifyRoutine", C::Callbacks, R::High, "Notified of every image load"},
    {"CmRegisterCallback", C::Callbacks, R::High, "Intercepts all registry operations"},
    {"CmRegisterCallbackEx", C::Callbacks, R::High, "Intercepts all registry operations"},
    {"KeRegisterBugCheckCallback", C::Callbacks, R::Medium, "Runs code on bug check"},
    {"IoRegisterShutdownNotification", C::Callbacks, R::Info, ""},
    // Driver loading, dynamic resolution, kernel tables
    {"ZwLoadDriver", C::DriverLoading, R::Critical, "Loads another kernel driver"},
    {"NtLoadDriver", C::DriverLoading, R::Critical, "Loads another kernel driver"},
    {"ZwSetSystemInformation", C::DriverLoading, R::Critical, "Changes system state (can load images, change code integrity)"},
    {"MmLoadSystemImage", C::DriverLoading, R::Critical, "Loads a kernel image"},
    {"MmGetSystemRoutineAddress", C::DynamicResolution, R::Medium, "Resolves kernel exports at runtime (hides imports)"},
    {"KeServiceDescriptorTable", C::DynamicResolution, R::Critical, "System service table (classic SSDT hooking target)"},
    {"ZwQuerySystemInformation", C::DynamicResolution, R::Medium, "Enumerates modules/processes/handles (kernel address disclosure)"},
    // Hardware access through the HAL
    {"HalSetBusDataByOffset", C::Hardware, R::Critical, "Writes PCI configuration space"},
    {"HalSetBusData", C::Hardware, R::Critical, "Writes PCI configuration space"},
    {"HalGetBusDataByOffset", C::Hardware, R::High, "Reads PCI configuration space"},
    {"HalGetBusData", C::Hardware, R::High, "Reads PCI configuration space"},
    {"HalTranslateBusAddress", C::Hardware, R::Medium, "Translates bus addresses to physical addresses"},
    {"READ_PORT_UCHAR", C::Hardware, R::High, "Reads an I/O port"},
    {"READ_PORT_USHORT", C::Hardware, R::High, "Reads an I/O port"},
    {"READ_PORT_ULONG", C::Hardware, R::High, "Reads an I/O port"},
    {"WRITE_PORT_UCHAR", C::Hardware, R::Critical, "Writes an I/O port"},
    {"WRITE_PORT_USHORT", C::Hardware, R::Critical, "Writes an I/O port"},
    {"WRITE_PORT_ULONG", C::Hardware, R::Critical, "Writes an I/O port"},
    // Registry and files
    {"ZwCreateKey", C::Registry, R::Medium, "Creates registry keys"},
    {"ZwSetValueKey", C::Registry, R::Medium, "Writes registry values (e.g. services, persistence)"},
    {"ZwDeleteKey", C::Registry, R::Medium, "Deletes registry keys"},
    {"ZwDeleteValueKey", C::Registry, R::Medium, "Deletes registry values"},
    {"RtlWriteRegistryValue", C::Registry, R::Medium, "Writes registry values"},
    {"ZwCreateFile", C::FileSystem, R::Medium, "Opens/creates files with kernel privileges"},
    {"ZwOpenFile", C::FileSystem, R::Medium, "Opens files with kernel privileges"},
    {"ZwWriteFile", C::FileSystem, R::Medium, "Writes files with kernel privileges"},
    {"ZwDeleteFile", C::FileSystem, R::Medium, "Deletes files with kernel privileges"},
    {"ZwSetInformationFile", C::FileSystem, R::Medium, "Renames/deletes files with kernel privileges"},
    {"IoCreateFile", C::FileSystem, R::Medium, "Opens/creates files with kernel privileges"},
    {"IoCreateFileEx", C::FileSystem, R::Medium, "Opens/creates files with kernel privileges"},
    // Validation of user input (mitigations, recorded as positives)
    {"ProbeForRead", C::Validation, R::Info, "Validates a user-mode buffer for reading (a mitigation)"},
    {"ProbeForWrite", C::Validation, R::Info, "Validates a user-mode buffer for writing (a mitigation)"},
    {"ExGetPreviousMode", C::Validation, R::Info, "Checks whether the caller was user mode (a mitigation)"},
    {"ObReferenceObjectByHandle", C::ObjectManager, R::Medium, "Resolves a caller-supplied handle; unsafe with KernelMode access"},
    {"ObReferenceObjectByName", C::ObjectManager, R::Medium, "Looks up an object by name"},
    // Pool
    {"ExAllocatePool", C::Pool, R::Medium, "Deprecated allocator; NonPagedPool is executable"},
    {"ExAllocatePoolWithTag", C::Pool, R::Info, ""},
    {"ExAllocatePoolWithQuotaTag", C::Pool, R::Info, ""},
    {"ExAllocatePool2", C::Pool, R::Info, ""},
    {"ExAllocatePool3", C::Pool, R::Info, ""},
    {"ExFreePool", C::Pool, R::Info, ""},
    {"ExFreePoolWithTag", C::Pool, R::Info, ""},
    // Devices and IRPs
    {"IoCreateDevice", C::Device, R::Info, ""},
    {"IoCreateDeviceSecure", C::Device, R::Info, ""},
    {"IoCreateSymbolicLink", C::Device, R::Info, "Exposes a device to user mode by name"},
    {"IoCreateUnprotectedSymbolicLink", C::Device, R::Medium, "Exposes a device to user mode with an unprotected link"},
    {"IoDeleteDevice", C::Device, R::Info, ""},
    {"IoDeleteSymbolicLink", C::Device, R::Info, ""},
    {"IoRegisterDeviceInterface", C::Device, R::Info, "Exposes a device to user mode by interface"},
    {"IofCompleteRequest", C::Irp, R::Info, ""},
    {"IofCallDriver", C::Irp, R::Info, ""},
    {"IoBuildDeviceIoControlRequest", C::Irp, R::Medium, "Sends IOCTLs to other drivers"},
    {"IoGetDeviceObjectPointer", C::Irp, R::Medium, "Opens another driver's device"},
    {"WdfVersionBind", C::Framework, R::Info, ""},
    {"FltRegisterFilter", C::FilterManager, R::Info, ""},
    {"FltCreateCommunicationPort", C::FilterManager, R::Medium, "Exposes a filter communication port to user mode"},
};

const Entry* find(std::string_view name) {
    for (const auto& e : kCatalog) {
        if (e.name == name) {
            return &e;
        }
    }
    return nullptr;
}

bool startsWith(std::string_view s, std::string_view p) {
    return s.substr(0, p.size()) == p;
}

ApiCategory categoryByPrefix(std::string_view n) {
    if (startsWith(n, "Wdf")) return C::Framework;
    if (startsWith(n, "Flt")) return C::FilterManager;
    if (startsWith(n, "Ndis") || startsWith(n, "Wsk") || startsWith(n, "Fwps") || startsWith(n, "Tdi")) return C::Networking;
    if (startsWith(n, "Hal") || startsWith(n, "READ_") || startsWith(n, "WRITE_")) return C::Hardware;
    if (startsWith(n, "Ke") && (n.find("Lock") != std::string_view::npos || n.find("Event") != std::string_view::npos ||
                                n.find("Wait") != std::string_view::npos || n.find("Mutex") != std::string_view::npos ||
                                n.find("Semaphore") != std::string_view::npos)) return C::Synchronization;
    if (startsWith(n, "ExAcquire") || startsWith(n, "ExRelease") || startsWith(n, "ExInitialize") ||
        (startsWith(n, "Ex") && n.find("Lock") != std::string_view::npos)) return C::Synchronization;
    if (startsWith(n, "ExAllocate") || startsWith(n, "ExFree")) return C::Pool;
    if (startsWith(n, "Mm")) return C::VirtualMemory;
    if (startsWith(n, "Ps")) return C::Process;
    if (startsWith(n, "Ob")) return C::ObjectManager;
    if (startsWith(n, "Se")) return C::Token;
    if (startsWith(n, "Cm") ||
        (n.find("Key") != std::string_view::npos && (startsWith(n, "Zw") || startsWith(n, "Nt")))) return C::Registry;
    if ((startsWith(n, "Zw") || startsWith(n, "Nt")) && n.find("File") != std::string_view::npos) return C::FileSystem;
    if (startsWith(n, "Iof") || n.find("Irp") != std::string_view::npos) return C::Irp;
    if (startsWith(n, "Io")) return C::Device;
    if (startsWith(n, "Rtl") || startsWith(n, "_") || startsWith(n, "mem") || startsWith(n, "str") ||
        startsWith(n, "wcs")) return C::Runtime;
    return C::Other;
}

} // namespace

ApiInfo classifyApi(std::string_view name) {
    ApiInfo info;
    if (const Entry* e = find(name)) {
        info.category = e->category;
        info.risk = e->risk;
        info.why = std::string(e->why);
        info.catalogued = true;
        return info;
    }
    info.category = categoryByPrefix(name);
    return info;
}

const char* categoryName(ApiCategory c) {
    switch (c) {
    case C::PhysicalMemory: return "Physical memory";
    case C::VirtualMemory: return "Virtual memory";
    case C::Pool: return "Pool";
    case C::Process: return "Process / thread";
    case C::Token: return "Token / security";
    case C::Callbacks: return "System callbacks";
    case C::Registry: return "Registry";
    case C::FileSystem: return "File system";
    case C::ObjectManager: return "Object manager";
    case C::Hardware: return "Hardware (HAL / ports)";
    case C::DriverLoading: return "Driver loading / system";
    case C::DynamicResolution: return "Dynamic resolution";
    case C::Validation: return "Input validation";
    case C::Device: return "Device";
    case C::Irp: return "IRP handling";
    case C::Synchronization: return "Synchronization";
    case C::Framework: return "KMDF";
    case C::FilterManager: return "Filter Manager";
    case C::Networking: return "Networking";
    case C::Runtime: return "Runtime library";
    case C::Other: break;
    }
    return "Other";
}

const char* riskName(ApiRisk r) {
    switch (r) {
    case R::Critical: return "critical";
    case R::High: return "high";
    case R::Medium: return "medium";
    case R::Info: break;
    }
    return "info";
}

} // namespace dasa::core::security
