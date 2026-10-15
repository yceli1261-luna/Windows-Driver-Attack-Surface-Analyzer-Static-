#include "core/ioctl/IoctlCodec.h"

#include <cstdio>

namespace dasa::core::ioctl {

namespace {

// FILE_DEVICE_* values (devioctl.h), carried over from v1's table.
const char* knownDeviceType(std::uint32_t t) {
    switch (t) {
    case 0x01: return "FILE_DEVICE_BEEP";
    case 0x02: return "FILE_DEVICE_CD_ROM";
    case 0x03: return "FILE_DEVICE_CD_ROM_FILE_SYSTEM";
    case 0x04: return "FILE_DEVICE_CONTROLLER";
    case 0x05: return "FILE_DEVICE_DATALINK";
    case 0x06: return "FILE_DEVICE_DFS";
    case 0x07: return "FILE_DEVICE_DISK";
    case 0x08: return "FILE_DEVICE_DISK_FILE_SYSTEM";
    case 0x09: return "FILE_DEVICE_FILE_SYSTEM";
    case 0x0A: return "FILE_DEVICE_INPORT_PORT";
    case 0x0B: return "FILE_DEVICE_KEYBOARD";
    case 0x0C: return "FILE_DEVICE_MAILSLOT";
    case 0x0D: return "FILE_DEVICE_MIDI_IN";
    case 0x0E: return "FILE_DEVICE_MIDI_OUT";
    case 0x0F: return "FILE_DEVICE_MOUSE";
    case 0x10: return "FILE_DEVICE_MULTI_UNC_PROVIDER";
    case 0x11: return "FILE_DEVICE_NAMED_PIPE";
    case 0x12: return "FILE_DEVICE_NETWORK";
    case 0x13: return "FILE_DEVICE_NETWORK_BROWSER";
    case 0x14: return "FILE_DEVICE_NETWORK_FILE_SYSTEM";
    case 0x15: return "FILE_DEVICE_NULL";
    case 0x16: return "FILE_DEVICE_PARALLEL_PORT";
    case 0x17: return "FILE_DEVICE_PHYSICAL_NETCARD";
    case 0x18: return "FILE_DEVICE_PRINTER";
    case 0x19: return "FILE_DEVICE_SCANNER";
    case 0x1A: return "FILE_DEVICE_SERIAL_MOUSE_PORT";
    case 0x1B: return "FILE_DEVICE_SERIAL_PORT";
    case 0x1C: return "FILE_DEVICE_SCREEN";
    case 0x1D: return "FILE_DEVICE_SOUND";
    case 0x1E: return "FILE_DEVICE_STREAMS";
    case 0x1F: return "FILE_DEVICE_TAPE";
    case 0x20: return "FILE_DEVICE_TAPE_FILE_SYSTEM";
    case 0x21: return "FILE_DEVICE_TRANSPORT";
    case 0x22: return "FILE_DEVICE_UNKNOWN";
    case 0x23: return "FILE_DEVICE_VIDEO";
    case 0x24: return "FILE_DEVICE_VIRTUAL_DISK";
    case 0x25: return "FILE_DEVICE_WAVE_IN";
    case 0x26: return "FILE_DEVICE_WAVE_OUT";
    case 0x27: return "FILE_DEVICE_8042_PORT";
    case 0x28: return "FILE_DEVICE_NETWORK_REDIRECTOR";
    case 0x29: return "FILE_DEVICE_BATTERY";
    case 0x2A: return "FILE_DEVICE_BUS_EXTENDER";
    case 0x2B: return "FILE_DEVICE_MODEM";
    case 0x2C: return "FILE_DEVICE_VDM";
    case 0x2D: return "FILE_DEVICE_MASS_STORAGE";
    case 0x2E: return "FILE_DEVICE_SMB";
    case 0x2F: return "FILE_DEVICE_KS";
    case 0x30: return "FILE_DEVICE_CHANGER";
    case 0x31: return "FILE_DEVICE_SMARTCARD";
    case 0x32: return "FILE_DEVICE_ACPI";
    case 0x33: return "FILE_DEVICE_DVD";
    case 0x34: return "FILE_DEVICE_FULLSCREEN_VIDEO";
    case 0x35: return "FILE_DEVICE_DFS_FILE_SYSTEM";
    case 0x36: return "FILE_DEVICE_DFS_VOLUME";
    case 0x37: return "FILE_DEVICE_SERENUM";
    case 0x38: return "FILE_DEVICE_TERMSRV";
    case 0x39: return "FILE_DEVICE_KSEC";
    case 0x3A: return "FILE_DEVICE_FIPS";
    case 0x3B: return "FILE_DEVICE_INFINIBAND";
    case 0x3E: return "FILE_DEVICE_VMBUS";
    case 0x3F: return "FILE_DEVICE_CRYPT_PROVIDER";
    case 0x40: return "FILE_DEVICE_WPD";
    case 0x41: return "FILE_DEVICE_BLUETOOTH";
    case 0x42: return "FILE_DEVICE_MT_COMPOSITE";
    case 0x43: return "FILE_DEVICE_MT_TRANSPORT";
    case 0x44: return "FILE_DEVICE_BIOMETRIC";
    case 0x45: return "FILE_DEVICE_PMI";
    case 0x46: return "FILE_DEVICE_EHSTOR";
    case 0x47: return "FILE_DEVICE_DEVAPI";
    case 0x48: return "FILE_DEVICE_GPIO";
    case 0x49: return "FILE_DEVICE_USBEX";
    case 0x50: return "FILE_DEVICE_CONSOLE";
    case 0x51: return "FILE_DEVICE_NFP";
    case 0x52: return "FILE_DEVICE_SYSENV";
    case 0x53: return "FILE_DEVICE_VIRTUAL_BLOCK";
    case 0x54: return "FILE_DEVICE_POINT_OF_SERVICE";
    case 0x55: return "FILE_DEVICE_STORAGE_REPLICATION";
    case 0x56: return "FILE_DEVICE_TRUST_ENV";
    case 0x57: return "FILE_DEVICE_UCM";
    case 0x58: return "FILE_DEVICE_UCMTCPCI";
    case 0x59: return "FILE_DEVICE_PERSISTENT_MEMORY";
    case 0x5A: return "FILE_DEVICE_NVDIMM";
    case 0x5B: return "FILE_DEVICE_HOLOGRAPHIC";
    case 0x5C: return "FILE_DEVICE_SDFXHCI";
    case 0x5D: return "FILE_DEVICE_UCMUCSI";
    case 0x60: return "FILE_DEVICE_USB4";
    case 0x61: return "FILE_DEVICE_SOUNDWIRE";
    case 0x62: return "FILE_DEVICE_FABRIC_NVME";
    case 0x63: return "FILE_DEVICE_SVM";
    case 0x64: return "FILE_DEVICE_HARDWARE_ACCELERATOR";
    case 0x65: return "FILE_DEVICE_I3C";
    default: return nullptr;
    }
}

constexpr std::uint32_t kFillPatterns[] = {0xCCCCCCCC, 0xCDCDCDCD, 0xFEEEFEEE,
                                           0xDEADBEEF, 0xBAADF00D, 0xFDFDFDFD};

} // namespace

DecodedIoctl decodeIoctl(std::uint32_t code) {
    DecodedIoctl d;
    d.code = code;
    d.deviceType = (code >> 16) & 0xFFFF;
    d.access = (code >> 14) & 0x3;
    d.function = (code >> 2) & 0xFFF;
    d.method = code & 0x3;
    return d;
}

std::string deviceTypeName(std::uint32_t deviceType) {
    if (const char* name = knownDeviceType(deviceType)) {
        return name;
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "0x%04X (%s)", deviceType, deviceType >= 0x8000 ? "vendor" : "unassigned");
    return buf;
}

const char* methodName(std::uint32_t method) {
    switch (method & 3) {
    case kMethodBuffered: return "METHOD_BUFFERED";
    case kMethodInDirect: return "METHOD_IN_DIRECT";
    case kMethodOutDirect: return "METHOD_OUT_DIRECT";
    default: return "METHOD_NEITHER";
    }
}

const char* accessName(std::uint32_t access) {
    switch (access & 3) {
    case 0: return "FILE_ANY_ACCESS";
    case 1: return "FILE_READ_ACCESS";
    case 2: return "FILE_WRITE_ACCESS";
    default: return "FILE_READ_ACCESS | FILE_WRITE_ACCESS";
    }
}

std::string hexCode(std::uint32_t code) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08X", code);
    return buf;
}

bool looksLikeIoctl(std::uint32_t v, bool strict) {
    if (v <= 0xFFFF) {
        return false; // device type 0
    }
    for (auto p : kFillPatterns) {
        if (v == p) {
            return false;
        }
    }
    const std::uint32_t device = v >> 16;
    if (strict) {
        return device >= 0x8000 && device < 0xFF00;
    }
    return knownDeviceType(device) != nullptr || (device >= 0x0200 && device < 0xFF00);
}

} // namespace dasa::core::ioctl
