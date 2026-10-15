#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dasa::core::driver {

enum class ModelKind {
    Unknown,
    Wdm,            // classic DriverObject->MajorFunction[] driver
    Kmdf,           // Kernel-Mode Driver Framework client
    Minifilter,     // Filter Manager minifilter (FltRegisterFilter)
    NdisMiniport,
    NdisFilter,
    NdisProtocol,
    Storport,
    ScsiPort,
    HidMinidriver,
    KernelStreaming,
};

enum class Confidence { Low, Medium, High };

const char* modelName(ModelKind kind);
const char* confidenceName(Confidence c);

struct DriverModel {
    ModelKind kind = ModelKind::Unknown;
    Confidence confidence = Confidence::Low;
    std::vector<std::string> evidence;            // why, in plain words
    std::vector<ModelKind> additionalFrameworks;  // e.g. KMDF driver that is also an NDIS miniport
};

/// IRP_MJ_* name for a major function code (0..0x1B), e.g. "IRP_MJ_DEVICE_CONTROL".
const char* irpMajorName(unsigned major);
inline constexpr unsigned kIrpMjMaximum = 0x1B;

// ---------------------------------------------------------------- WDM ----

struct DispatchEntry {
    unsigned major = 0;
    std::uint64_t handler = 0;     // RVA written into MajorFunction[major]
    std::uint64_t setAt = 0;       // RVA of the store instruction
    std::uint64_t inFunction = 0;  // function containing the store
    std::string how;               // "direct store", "loop over all entries", "rep stos"
    bool handlerIsFunction = false; // handler RVA is a discovered function start
};

/// A store into a DRIVER_OBJECT field other than MajorFunction[].
struct DriverObjectWrite {
    std::uint32_t offset = 0;
    std::string field;            // "DriverUnload", "DriverStartIo", ..., or "DriverExtension->AddDevice"
    std::optional<std::uint64_t> value; // RVA when the stored value is a code/data address
    std::uint64_t setAt = 0;
    std::uint64_t inFunction = 0;
};

// --------------------------------------------------------------- KMDF ----

/// WDF_BIND_INFO, the structure FxDriverEntry hands to WdfVersionBind.
struct WdfBindInfo {
    std::uint64_t rva = 0;
    std::uint32_t size = 0;
    std::uint32_t major = 0;
    std::uint32_t minor = 0;
    std::uint32_t build = 0;
    std::uint32_t functionCount = 0;
    std::uint64_t functionTableVariable = 0; // RVA of WdfFunctions_01xxx
};

/// A call through the WDF function table.
struct WdfCall {
    std::uint64_t rva = 0;
    std::uint64_t inFunction = 0;
    std::uint32_t index = 0;
    std::string name; // e.g. "WdfIoQueueCreate"
};

struct WdfCallback {
    std::string name;            // e.g. "EvtIoDeviceControl"
    std::uint64_t function = 0;  // RVA
    bool isFunction = false;     // a discovered function starts there
};

/// One WdfIoQueueCreate call with its WDF_IO_QUEUE_CONFIG recovered.
struct WdfQueue {
    std::uint64_t createCall = 0;
    std::uint64_t inFunction = 0;
    bool configResolved = false; // config pointer traced to a stack structure
    std::string dispatchType;    // Sequential / Parallel / Manual / unknown
    std::optional<bool> defaultQueue;
    std::vector<WdfCallback> callbacks;
};

/// One WdfDriverCreate call with its WDF_DRIVER_CONFIG recovered.
struct WdfDriverRegistration {
    std::uint64_t createCall = 0;
    std::uint64_t inFunction = 0;
    bool configResolved = false;
    std::vector<WdfCallback> callbacks; // EvtDriverDeviceAdd, EvtDriverUnload
};

struct WdfIoTypeSetting {
    std::uint64_t call = 0;
    std::string ioType; // Buffered / Direct / Neither / BufferedOrDirect / unknown
};

// ------------------------------------------------------------ results ----

struct DriverAnalysis {
    DriverModel model;

    // The driver's own DriverEntry, after stepping through compiler/WDF
    // stubs (GsDriverEntry, FxDriverEntry) that only forward the arguments.
    std::optional<std::uint64_t> driverEntry;
    std::vector<std::uint64_t> entryChain; // PE entry point ... DriverEntry
    std::string driverEntryNote;

    std::vector<DispatchEntry> majorFunctions; // recovered entries, sorted by major
    std::vector<DriverObjectWrite> driverObjectWrites;

    std::optional<WdfBindInfo> wdfBind;
    std::vector<WdfCall> wdfCalls;
    std::vector<WdfDriverRegistration> wdfDrivers;
    std::vector<WdfQueue> wdfQueues;
    std::vector<WdfIoTypeSetting> wdfIoTypes;

    std::vector<std::string> notes; // limitations hit while analysing this driver

    const DispatchEntry* dispatchFor(unsigned major) const {
        for (const auto& e : majorFunctions) {
            if (e.major == major) {
                return &e;
            }
        }
        return nullptr;
    }
};

} // namespace dasa::core::driver
