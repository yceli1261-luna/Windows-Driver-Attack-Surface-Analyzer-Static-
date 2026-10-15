#include "core/pe/ImageStrings.h"

#include <cstdio>
#include <span>

namespace dasa::core::pe {

namespace {

constexpr std::size_t kMaxUnicodeStringChars = 512;

std::uint64_t readLe(std::span<const std::uint8_t> b, std::size_t n) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n && i < b.size(); ++i) {
        v |= static_cast<std::uint64_t>(b[i]) << (8 * i);
    }
    return v;
}

} // namespace

std::optional<std::string> utf16At(const PEImage& image, std::uint64_t rva, std::size_t maxChars) {
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

std::optional<std::string> asciiAt(const PEImage& image, std::uint64_t rva, std::size_t maxChars) {
    const auto bytes = image.bytesAt(rva);
    std::string out;
    for (std::size_t i = 0; i < bytes.size() && i <= maxChars; ++i) {
        const auto c = bytes[i];
        if (c == 0) {
            return out.empty() ? std::nullopt : std::optional(out);
        }
        if (c < 0x20 || c >= 0x7F) {
            return std::nullopt;
        }
        out.push_back(static_cast<char>(c));
    }
    return std::nullopt;
}

std::optional<std::string> unicodeStringAt(const PEImage& image, std::uint64_t rva) {
    const bool x64 = image.machine == 0x8664;
    const auto b = image.bytesAt(rva);
    if (b.size() < (x64 ? 16u : 8u)) {
        return std::nullopt;
    }
    const auto length = static_cast<std::uint16_t>(readLe(b, 2));
    const auto maxLength = static_cast<std::uint16_t>(readLe(b.subspan(2), 2));
    const std::uint64_t buffer = readLe(b.subspan(x64 ? 8 : 4), x64 ? 8 : 4);
    if (length == 0 || length % 2 != 0 || length > maxLength || length > kMaxUnicodeStringChars * 2) {
        return std::nullopt;
    }
    const auto bufferRva = image.vaToRva(buffer);
    if (!bufferRva) {
        return std::nullopt;
    }
    return utf16At(image, *bufferRva, length / 2);
}

std::string guidAt(const PEImage& image, std::uint64_t rva) {
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

} // namespace dasa::core::pe
