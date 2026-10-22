#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/driver/DriverModel.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/ioctl/IoctlExtractor.h"
#include "core/pe/PEImage.h"

namespace dasa::core::dataflow {

/// What makes a value user-controlled. A value can carry several.
enum TaintLabel : std::uint32_t {
    kUserBuffer = 1u << 0,  // points at a kernel copy of the request's data (SystemBuffer, WDF input buffer)
    kUserPointer = 1u << 1, // a raw user-mode address (Type3InputBuffer, Irp->UserBuffer, unsafe WDF buffers)
    kUserData = 1u << 2,    // a value read from request data (or computed from one)
    kUserLength = 1u << 3,  // a length the caller chose (InputBufferLength, OutputBufferLength, Write.Length)
};

/// "request data", "user-mode pointer", ... joined with ", ".
std::string describeLabels(std::uint32_t labels);

enum class Severity { Medium, High, Critical };
const char* severityName(Severity s);

enum class SinkKind {
    ApiArgument,  // a user-controlled argument to a sensitive kernel API
    Instruction,  // a privileged instruction with user-controlled operands (wrmsr, out, ...)
    MemoryWrite,  // a store through a user-controlled address
    MemoryRead,   // a load through a user-controlled or unprobed user address
};
const char* sinkKindName(SinkKind k);

/// One operand of a sink and where its value came from.
struct TaintedOperand {
    std::string name;      // "PhysicalAddress", "ecx (MSR index)", "address"
    std::uint32_t labels = 0;
    std::string source;    // "[Irp->AssociatedIrp.SystemBuffer + 0x8]"
    std::uint64_t sourceAt = 0; // RVA where the source value was read
};

/// User-controlled data reaching a sensitive operation.
struct TaintFlow {
    SinkKind kind = SinkKind::ApiArgument;
    std::string sink;        // "MmMapIoSpace", "wrmsr", "store", "load"
    std::string impact;      // what an attacker gets, in plain words
    Severity severity = Severity::High;
    std::uint64_t at = 0;            // RVA of the call / instruction
    std::uint64_t function = 0;      // function containing it
    std::string entry;               // "IRP_MJ_DEVICE_CONTROL", "EvtIoDeviceControl", ...
    std::vector<std::uint64_t> path; // entry function ... `function`
    std::vector<TaintedOperand> operands;
    std::vector<std::uint32_t> ioctls; // codes whose case leads here
    bool ioctlsExact = false;          // from the case branch, not just "compared in this function"
    // The handler reads Irp->RequestorMode: it may only trust such data
    // from kernel-mode callers (a check this analysis can't evaluate).
    bool requestorModeChecked = false;
};

/// A sensitive API call reached from a request handler, with what is known
/// about each argument - including calls whose arguments are constants.
struct CheckedCall {
    std::string api;
    std::uint64_t at = 0;
    std::uint64_t function = 0;
    std::string entry;
    struct Arg {
        std::string name;
        enum class Kind { UserControlled, Constant, Unknown } kind = Kind::Unknown;
        std::int64_t value = 0;     // Constant
        std::uint32_t labels = 0;   // UserControlled
    };
    std::vector<Arg> args;
    bool anyUserControlled() const;
};

struct DataFlowAnalysis {
    std::vector<TaintFlow> flows;       // most severe first
    std::vector<CheckedCall> checkedCalls;
    std::vector<std::string> entries;   // handlers analysed, e.g. "IRP_MJ_DEVICE_CONTROL (sub_1100)"
    std::size_t functionsAnalysed = 0;
    std::vector<std::string> notes;     // limits that applied to this driver
};

/// Tracks request data from the driver's user-request handlers (WDM
/// IRP_MJ_DEVICE_CONTROL / INTERNAL_DEVICE_CONTROL / WRITE and KMDF
/// EvtIoDeviceControl / EvtIoInternalDeviceControl / EvtIoWrite) through
/// registers, stack slots and direct calls (depth-limited, with argument
/// and return-value passing) to sensitive API arguments, privileged
/// instructions and memory accesses through user-controlled addresses.
///
/// Sources: Irp->AssociatedIrp.SystemBuffer (data it points at), the
/// IO_STACK_LOCATION buffer lengths and Type3InputBuffer, Irp->UserBuffer,
/// the KMDF EvtIo* length arguments and WdfRequestRetrieve*Buffer outputs.
/// ProbeForRead/ProbeForWrite on a user pointer marks it probed.
///
/// Within a function, states flow along basic-block edges and are joined
/// where paths meet (a fixpoint), then sinks are reported from the settled
/// states. Memory accesses count as sinks only when the address is a
/// pointer read from request data (plus constants) or an unprobed user
/// pointer; offsets and indexes into buffers don't, because bounds checks
/// aren't modelled. Inline probes (`cmp p, MmUserProbeAddress` or the
/// constant boundary) count as probes.
///
/// Limits: x64 only; path-insensitive (values from different paths are
/// merged); heap/global memory isn't tracked (data stored to a pool buffer
/// and read back is lost); indirect calls aren't followed; switch-table
/// cases aren't reached (Phase 3 doesn't follow jump tables); range checks
/// aren't recognised - a flow means "can reach", not "is unchecked".
DataFlowAnalysis analyzeDataFlow(const pe::PEImage& image, const functions::FunctionSet& functions,
                                 const driver::DriverAnalysis& driver, const ioctl::IoctlAnalysis& ioctls);

} // namespace dasa::core::dataflow
