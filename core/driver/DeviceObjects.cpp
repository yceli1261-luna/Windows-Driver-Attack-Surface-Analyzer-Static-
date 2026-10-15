#include "core/driver/DeviceObjects.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>
#include <string_view>

#include <spdlog/spdlog.h>

#include "core/driver/ValueTracker.h"
#include "core/driver/WdfFunctionTable.h"

namespace dasa::core::driver {

using disasm::Reg;
using Kind = Value::Kind;

namespace {

constexpr std::size_t kMaxNameChars = 512;

std::string_view importFunction(const std::string& importName) {
    const auto bang = importName.rfind('!');
    return bang == std::string::npos ? std::string_view(importName)
                                     : std::string_view(importName).substr(bang + 1);
}

std::uint64_t readLe(std::span<const std::uint8_t> b, std::size_t n) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n && i < b.size(); ++i) {
        v |= static_cast<std::uint64_t>(b[i]) << (8 * i);
    }
    return v;
}

// UTF-16LE at `rva` up to a NUL or `maxChars` characters (a counted
// UNICODE_STRING needn't be NUL-terminated); non-ASCII becomes '?'. Fails
// only if the image ends first.
std::optional<std::string> utf16At(const pe::PEImage& image, std::uint64_t rva, std::size_t maxChars) {
    const auto bytes = image.bytesAt(rva);
    std::string out;
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        if (out.size() == maxChars) {
            return out;
        }
        const unsigned c = bytes[i] | (bytes[i + 1] << 8);
        if (c == 0) {
            return out;
        }
        out.push_back(c < 0x80 ? static_cast<char>(c) : '?');
    }
    return std::nullopt;
}

// A UNICODE_STRING {Length, MaximumLength, Buffer} stored at `rva`
// (RTL_CONSTANT_STRING / DECLARE_CONST_UNICODE_STRING in .rdata/.data).
std::optional<std::string> unicodeStringAt(const pe::PEImage& image, std::uint64_t rva) {
    const bool x64 = image.machine == 0x8664;
    const auto b = image.bytesAt(rva);
    if (b.size() < (x64 ? 16u : 8u)) {
        return std::nullopt;
    }
    const auto length = static_cast<std::uint16_t>(readLe(b, 2));
    const auto maxLength = static_cast<std::uint16_t>(readLe(b.subspan(2), 2));
    const std::uint64_t buffer = readLe(b.subspan(x64 ? 8 : 4), x64 ? 8 : 4);
    if (length == 0 || length % 2 != 0 || length > maxLength || length > kMaxNameChars * 2) {
        return std::nullopt;
    }
    const auto bufferRva = image.vaToRva(buffer);
    if (!bufferRva) {
        return std::nullopt;
    }
    auto s = utf16At(image, *bufferRva, length / 2);
    if (s && s->size() > length / 2) {
        s->resize(length / 2);
    }
    return s;
}

std::string guidAt(const pe::PEImage& image, std::uint64_t rva) {
    const auto b = image.bytesAt(rva);
    if (b.size() < 16) {
        return {};
    }
    char buf[48];
    std::snprintf(buf, sizeof(buf), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  static_cast<unsigned>(readLe(b, 4)), static_cast<unsigned>(readLe(b.subspan(4), 2)),
                  static_cast<unsigned>(readLe(b.subspan(6), 2)), b[8], b[9], b[10], b[11], b[12], b[13],
                  b[14], b[15]);
    return buf;
}

class Collector : public TrackerHooks {
public:
    Collector(const pe::PEImage& image, DeviceAnalysis& out) : m_image(image), m_out(out) {}

    std::uint64_t currentFunction = 0;
    std::map<std::pair<Reg, std::int64_t>, std::string> stackStrings; // per function
    std::map<std::uint64_t, std::string> globalStrings;
    std::map<std::uint64_t, std::size_t> wdfDeviceInFunction; // function -> index in devices
    std::size_t unresolved = 0;
    // First pass: only collect RtlInitUnicodeString results, so a global
    // UNICODE_STRING initialised in one function resolves where another
    // function passes it to IoCreateDevice.
    bool stringsOnly = false;

    void onCall(const disasm::Instruction& insn, const CallInfo& info, const TrackerState& s) override {
        if (stringsOnly && (info.wdfIndex || importFunction(info.importName) != "RtlInitUnicodeString")) {
            return;
        }
        if (info.wdfIndex) {
            onWdfCall(insn, *info.wdfIndex, s);
            return;
        }
        if (info.importName.empty()) {
            return;
        }
        const std::string_view fn = importFunction(info.importName);
        if (fn == "RtlInitUnicodeString") {
            // RtlInitUnicodeString(Destination, SourceString)
            const Value src = s.reg(Reg::Rdx);
            if (!src.is(Kind::Address)) {
                return;
            }
            const auto text = utf16At(m_image, static_cast<std::uint64_t>(src.a), kMaxNameChars);
            if (!text) {
                return;
            }
            const Value dst = s.reg(Reg::Rcx);
            if (dst.is(Kind::Stack)) {
                stackStrings[{dst.base, dst.a}] = *text;
            } else if (dst.is(Kind::Address)) {
                globalStrings[static_cast<std::uint64_t>(dst.a)] = *text;
            }
        } else if (fn == "IoCreateDevice" || fn == "IoCreateDeviceSecure") {
            // IoCreateDevice(DriverObject, ExtensionSize, DeviceName, DeviceType,
            //                Characteristics, Exclusive, DeviceObject)
            // IoCreateDeviceSecure(..., Exclusive, DefaultSDDLString, ClassGuid, DeviceObject)
            DeviceObjectInfo d;
            d.api = std::string(fn);
            d.at = insn.rva;
            d.inFunction = currentFunction;
            const Value name = s.reg(Reg::R8);
            if (name.is(Kind::Immediate) && name.a == 0) {
                d.nameResolved = true; // explicitly unnamed
            } else if (auto text = resolve(name)) {
                d.name = *text;
                d.nameResolved = true;
            } else {
                ++unresolved;
            }
            d.deviceType = immediate(s.reg(Reg::R9));
            d.characteristics = immediate(s.stackArg(0x20));
            if (auto ex = immediate(s.stackArg(0x28))) {
                d.exclusive = (*ex & 0xFF) != 0;
            }
            if (fn == "IoCreateDeviceSecure") {
                if (auto sddl = resolve(s.stackArg(0x30))) {
                    d.sddl = *sddl;
                }
            }
            m_out.devices.push_back(std::move(d));
        } else if (fn == "IoCreateSymbolicLink" || fn == "IoCreateUnprotectedSymbolicLink") {
            // IoCreateSymbolicLink(SymbolicLinkName, DeviceName)
            SymbolicLinkInfo l;
            l.api = std::string(fn);
            l.link = resolve(s.reg(Reg::Rcx)).value_or("");
            l.target = resolve(s.reg(Reg::Rdx)).value_or("");
            l.at = insn.rva;
            l.inFunction = currentFunction;
            m_out.symbolicLinks.push_back(std::move(l));
        } else if (fn == "IoRegisterDeviceInterface") {
            // IoRegisterDeviceInterface(PDO, InterfaceClassGuid, ReferenceString, SymbolicLinkName)
            DeviceInterfaceInfo i;
            i.api = std::string(fn);
            const Value g = s.reg(Reg::Rdx);
            if (g.is(Kind::Address)) {
                i.guid = guidAt(m_image, static_cast<std::uint64_t>(g.a));
            }
            i.at = insn.rva;
            i.inFunction = currentFunction;
            m_out.interfaces.push_back(std::move(i));
        }
    }

private:
    static std::optional<std::uint32_t> immediate(const Value& v) {
        if (v.is(Kind::Immediate)) {
            return static_cast<std::uint32_t>(v.a);
        }
        return std::nullopt;
    }

    std::optional<std::string> resolve(const Value& v) const {
        if (v.is(Kind::Stack)) {
            auto it = stackStrings.find({v.base, v.a});
            if (it != stackStrings.end()) {
                return it->second;
            }
        } else if (v.is(Kind::Address)) {
            const auto rva = static_cast<std::uint64_t>(v.a);
            auto it = globalStrings.find(rva);
            if (it != globalStrings.end()) {
                return it->second;
            }
            return unicodeStringAt(m_image, rva);
        }
        return std::nullopt;
    }

    DeviceObjectInfo& wdfDevice(const disasm::Instruction& insn, const char* api) {
        auto it = wdfDeviceInFunction.find(currentFunction);
        if (it != wdfDeviceInFunction.end()) {
            return m_out.devices[it->second];
        }
        DeviceObjectInfo d;
        d.api = api;
        d.at = insn.rva;
        d.inFunction = currentFunction;
        m_out.devices.push_back(std::move(d));
        wdfDeviceInFunction[currentFunction] = m_out.devices.size() - 1;
        return m_out.devices.back();
    }

    void onWdfCall(const disasm::Instruction& insn, std::uint32_t index, const TrackerState& s) {
        const char* n = wdfFunctionName(index);
        if (n == nullptr) {
            return;
        }
        const std::string_view name(n);
        // WDF DDIs take (DriverGlobals, Object, args...): args start at r8.
        if (name == "WdfDeviceInitAssignName") {
            DeviceObjectInfo& d = wdfDevice(insn, n);
            if (auto text = resolve(s.reg(Reg::R8))) {
                d.name = *text;
                d.nameResolved = true;
            } else {
                ++unresolved;
            }
        } else if (name == "WdfControlDeviceInitAllocate") {
            DeviceObjectInfo& d = wdfDevice(insn, n);
            d.api = n;
            if (auto sddl = resolve(s.reg(Reg::R8))) {
                d.sddl = *sddl;
            }
        } else if (name == "WdfDeviceInitAssignSDDLString") {
            if (auto sddl = resolve(s.reg(Reg::R8))) {
                wdfDevice(insn, "WdfDeviceInitAssignName").sddl = *sddl;
            }
        } else if (name == "WdfDeviceInitSetDeviceType") {
            if (auto t = immediate(s.reg(Reg::R8))) {
                pendingType[currentFunction] = *t;
            }
        } else if (name == "WdfDeviceInitSetCharacteristics") {
            if (auto c = immediate(s.reg(Reg::R8))) {
                pendingCharacteristics[currentFunction] |= *c;
            }
        } else if (name == "WdfDeviceInitSetExclusive") {
            if (auto e = immediate(s.reg(Reg::R8))) {
                pendingExclusive[currentFunction] = (*e & 0xFF) != 0;
            }
        } else if (name == "WdfDeviceCreateSymbolicLink") {
            SymbolicLinkInfo l;
            l.api = n;
            l.link = resolve(s.reg(Reg::R8)).value_or("");
            l.at = insn.rva;
            l.inFunction = currentFunction;
            m_out.symbolicLinks.push_back(std::move(l));
        } else if (name == "WdfDeviceCreateDeviceInterface") {
            DeviceInterfaceInfo i;
            i.api = n;
            const Value g = s.reg(Reg::R8);
            if (g.is(Kind::Address)) {
                i.guid = guidAt(m_image, static_cast<std::uint64_t>(g.a));
            }
            i.at = insn.rva;
            i.inFunction = currentFunction;
            m_out.interfaces.push_back(std::move(i));
        }
    }

public:
    // WDF device properties set in a function; applied to that function's
    // named/control device once all functions are walked.
    std::map<std::uint64_t, std::uint32_t> pendingType;
    std::map<std::uint64_t, std::uint32_t> pendingCharacteristics;
    std::map<std::uint64_t, bool> pendingExclusive;

    void applyPending() {
        for (const auto& [fn, idx] : wdfDeviceInFunction) {
            DeviceObjectInfo& d = m_out.devices[idx];
            if (auto it = pendingType.find(fn); it != pendingType.end()) {
                d.deviceType = it->second;
            }
            if (auto it = pendingCharacteristics.find(fn); it != pendingCharacteristics.end()) {
                d.characteristics = it->second;
            }
            if (auto it = pendingExclusive.find(fn); it != pendingExclusive.end()) {
                d.exclusive = it->second;
            }
        }
    }

private:
    const pe::PEImage& m_image;
    DeviceAnalysis& m_out;
};

bool startsWithCi(const std::string& s, std::string_view prefix) {
    if (s.size() < prefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != std::tolower(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

// UTF-16LE strings in non-code sections that name devices or links.
void scanStrings(const pe::PEImage& image, DeviceAnalysis& out) {
    std::set<std::string> devices, links;
    for (const auto& section : image.sections) {
        if (section.isExecutable()) {
            continue;
        }
        const auto bytes = image.bytesAt(section.virtualAddress)
                               .subspan(0, std::min<std::size_t>(std::max(section.virtualSize, section.rawSize),
                                                                 image.bytesAt(section.virtualAddress).size()));
        std::string current;
        auto flush = [&] {
            if (current.size() >= 4) {
                if (startsWithCi(current, "\\Device\\")) {
                    devices.insert(current);
                } else if (startsWithCi(current, "\\DosDevices\\") || startsWithCi(current, "\\??\\") ||
                           startsWithCi(current, "\\GLOBAL??\\")) {
                    links.insert(current);
                }
            }
            current.clear();
        };
        for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
            const unsigned c = bytes[i] | (bytes[i + 1] << 8);
            if (c >= 0x20 && c < 0x7F) {
                if (current.empty() && c != '\\') {
                    continue;
                }
                current.push_back(static_cast<char>(c));
                if (current.size() > kMaxNameChars) {
                    current.clear();
                }
            } else {
                flush();
            }
        }
        flush();
    }
    out.deviceNameStrings.assign(devices.begin(), devices.end());
    out.linkNameStrings.assign(links.begin(), links.end());
}

} // namespace

DeviceAnalysis analyzeDevices(const pe::PEImage& image, const functions::FunctionSet& set,
                              const DriverAnalysis& driver) {
    DeviceAnalysis out;
    if (image.machine != 0x8664 && image.machine != 0x014C) {
        return out;
    }
    TrackerContext ctx = makeTrackerContext(image, set);
    if (driver.wdfBind) {
        ctx.wdfTableVariable = driver.wdfBind->functionTableVariable;
    }

    Collector c(image, out);
    for (bool stringsOnly : {true, false}) {
        c.stringsOnly = stringsOnly;
        for (const auto& fn : set.functions) {
            TrackerState state;
            c.currentFunction = fn.rva;
            c.stackStrings.clear();
            trackFunction(fn, ctx, state, c);
        }
    }
    c.applyPending();
    scanStrings(image, out);

    if (image.machine != 0x8664 && !out.devices.empty()) {
        out.notes.push_back("x86: device type, characteristics and SDDL are passed on the stack and are "
                            "only decoded for x64.");
    }
    if (c.unresolved > 0) {
        out.notes.push_back(std::to_string(c.unresolved) +
                            " device name(s) couldn't be resolved to a string (built at runtime or passed "
                            "in from elsewhere).");
    }
    spdlog::info("Devices in {}: {} device objects, {} symbolic links, {} interfaces, {}/{} name strings",
                 image.fileName, out.devices.size(), out.symbolicLinks.size(), out.interfaces.size(),
                 out.deviceNameStrings.size(), out.linkNameStrings.size());
    return out;
}

} // namespace dasa::core::driver
