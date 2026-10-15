#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/driver/DriverModel.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/pe/PEImage.h"

namespace dasa::core::driver {

inline constexpr std::uint32_t kFileDeviceSecureOpen = 0x00000100; // FILE_DEVICE_SECURE_OPEN

/// A device object the driver creates, as seen at the creation call.
struct DeviceObjectInfo {
    std::string api;                          // IoCreateDevice, IoCreateDeviceSecure, WdfDeviceInitAssignName, WdfControlDeviceInitAllocate
    std::string name;                         // empty = unnamed or not resolved
    bool nameResolved = false;
    std::optional<std::uint32_t> deviceType;  // FILE_DEVICE_*
    std::optional<std::uint32_t> characteristics;
    std::optional<bool> exclusive;
    std::string sddl;                         // IoCreateDeviceSecure / WDF SDDL string, if resolved
    std::uint64_t at = 0;
    std::uint64_t inFunction = 0;

    std::optional<bool> secureOpen() const {
        if (!characteristics) {
            return std::nullopt;
        }
        return (*characteristics & kFileDeviceSecureOpen) != 0;
    }
};

struct SymbolicLinkInfo {
    std::string api;    // IoCreateSymbolicLink, IoCreateUnprotectedSymbolicLink, WdfDeviceCreateSymbolicLink
    std::string link;   // e.g. \DosDevices\Foo
    std::string target; // device name (WDM; empty for WDF, which links the device being created)
    std::uint64_t at = 0;
    std::uint64_t inFunction = 0;
};

struct DeviceInterfaceInfo {
    std::string api;  // IoRegisterDeviceInterface, WdfDeviceCreateDeviceInterface
    std::string guid; // {XXXXXXXX-XXXX-...}, empty if not resolved
    std::uint64_t at = 0;
    std::uint64_t inFunction = 0;
};

struct DeviceAnalysis {
    std::vector<DeviceObjectInfo> devices;
    std::vector<SymbolicLinkInfo> symbolicLinks;
    std::vector<DeviceInterfaceInfo> interfaces;

    // Every \Device\..., \DosDevices\..., \??\... and \GLOBAL??\... string in
    // the image, whether or not a creation call using it was recovered.
    std::vector<std::string> deviceNameStrings;
    std::vector<std::string> linkNameStrings;

    std::vector<std::string> notes;
};

/// Recovers device objects, symbolic links and device interfaces from the
/// calls that create them: RtlInitUnicodeString / static UNICODE_STRINGs
/// are tracked into IoCreateDevice(Secure), IoCreateSymbolicLink,
/// IoRegisterDeviceInterface and the KMDF equivalents (WdfDeviceInitAssign
/// Name/SDDLString/SetDeviceType/SetCharacteristics/SetExclusive,
/// WdfControlDeviceInitAllocate, WdfDeviceCreateSymbolicLink,
/// WdfDeviceCreateDeviceInterface). Unlike v1, a link is paired with the
/// device name actually passed to IoCreateSymbolicLink, not by suffix.
///
/// Limits: names built at runtime (e.g. with an instance number) and
/// arguments not held in registers/stack slots the tracker follows are
/// reported as unresolved; x64 argument conventions only for stack args.
DeviceAnalysis analyzeDevices(const pe::PEImage& image, const functions::FunctionSet& functions,
                              const DriverAnalysis& driver);

} // namespace dasa::core::driver
