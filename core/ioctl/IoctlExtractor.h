#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/driver/DriverModel.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/ioctl/IoctlCodec.h"
#include "core/pe/PEImage.h"

namespace dasa::core::ioctl {

/// How an IOCTL code was found, from most to least certain.
enum class IoctlEvidence {
    // Compared against the tracked IoControlCode (IRP stack location for
    // WDM, the EvtIo* IoControlCode argument for KMDF) in a handler or a
    // function it hands the request to. Includes `sub` switch chains.
    TrackedCompare,
    // An IOCTL-shaped constant compared in a handler where the code value
    // itself couldn't be tracked (e.g. read through a helper or structure).
    HandlerConstant,
    // No handler was recovered: vendor-device-type constants compared
    // anywhere in the code, kept only for the device types that recur.
    ImageScan,
};

const char* evidenceName(IoctlEvidence e);

struct ExtractedIoctl {
    DecodedIoctl decoded;
    std::string handler;            // "IRP_MJ_DEVICE_CONTROL", "EvtIoDeviceControl (queue 1)", ...
    std::uint64_t handlerFunction = 0;
    std::uint64_t comparedIn = 0;   // function containing the comparison
    std::uint64_t at = 0;           // RVA of the cmp/sub
    std::optional<std::uint64_t> caseTarget; // where control goes when the code matches
    IoctlEvidence evidence = IoctlEvidence::HandlerConstant;
};

/// A switch over IOCTL codes compiled to a jump table: the range is known,
/// the individual cases are not decoded yet.
struct IoctlSwitchRange {
    std::uint64_t at = 0;
    std::uint64_t inFunction = 0;
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    std::string handler;
};

struct IoctlAnalysis {
    std::vector<ExtractedIoctl> ioctls; // unique by code, sorted by code
    std::vector<IoctlSwitchRange> switchRanges;
    std::vector<std::string> anchors;   // handlers that were analysed
    std::vector<std::string> notes;
};

/// Extracts the IOCTL codes a driver handles, starting from the request
/// handlers Phase 4 recovered (WDM IRP_MJ_DEVICE_CONTROL /
/// INTERNAL_DEVICE_CONTROL routines, KMDF EvtIoDeviceControl /
/// EvtIoInternalDeviceControl / EvtIoDefault callbacks) and following the
/// functions they pass the IRP or the code to (depth 3).
///
/// Limits: jump-table switches yield a code range, not the cases; codes
/// compared after being stored to and reloaded from a structure other than
/// the IRP are only found as HandlerConstant; KMDF requests read via
/// WdfRequestGetParameters (EvtIoDefault) fall back to HandlerConstant.
IoctlAnalysis extractIoctls(const pe::PEImage& image, const functions::FunctionSet& functions,
                            const driver::DriverAnalysis& driver);

} // namespace dasa::core::ioctl
