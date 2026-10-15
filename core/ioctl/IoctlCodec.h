#pragma once

#include <cstdint>
#include <string>

namespace dasa::core::ioctl {

// CTL_CODE(DeviceType, Function, Method, Access) layout (devioctl.h):
//   bits 31..16 DeviceType, 15..14 Access, 13..2 Function, 1..0 Method.
inline constexpr std::uint32_t kMethodBuffered = 0;
inline constexpr std::uint32_t kMethodInDirect = 1;
inline constexpr std::uint32_t kMethodOutDirect = 2;
inline constexpr std::uint32_t kMethodNeither = 3;
inline constexpr std::uint32_t kFileAnyAccess = 0;

struct DecodedIoctl {
    std::uint32_t code = 0;
    std::uint32_t deviceType = 0;
    std::uint32_t function = 0;
    std::uint32_t method = 0;
    std::uint32_t access = 0;

    bool isMethodNeither() const { return method == kMethodNeither; }
    bool isAnyAccess() const { return access == kFileAnyAccess; }
    /// Function codes 0x800 and up are vendor-defined (Microsoft reserves the rest).
    bool isCustomFunction() const { return function >= 0x800; }
};

DecodedIoctl decodeIoctl(std::uint32_t code);
constexpr std::uint32_t ctlCode(std::uint32_t deviceType, std::uint32_t function, std::uint32_t method,
                                std::uint32_t access) {
    return (deviceType << 16) | (access << 14) | (function << 2) | method;
}

/// "FILE_DEVICE_UNKNOWN", or "0x8001 (vendor)" / "0x0070 (unassigned)".
std::string deviceTypeName(std::uint32_t deviceType);
const char* methodName(std::uint32_t method);  // METHOD_BUFFERED, ...
const char* accessName(std::uint32_t access);  // FILE_ANY_ACCESS, ...
std::string hexCode(std::uint32_t code);       // 0x0022200B

/// Whether a 32-bit constant is plausible as an IOCTL code. `strict` keeps
/// only vendor device types (>= 0x8000): used when a constant has no other
/// evidence of being an IOCTL, because small Microsoft device types collide
/// with ordinary constants.
bool looksLikeIoctl(std::uint32_t value, bool strict);

} // namespace dasa::core::ioctl
