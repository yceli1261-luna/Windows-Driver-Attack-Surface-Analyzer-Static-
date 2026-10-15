#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "core/pe/PEImage.h"

namespace dasa::core::pe {

/// UTF-16LE text at `rva`, up to a NUL or `maxChars` characters (a counted
/// UNICODE_STRING needn't be NUL-terminated). Non-ASCII becomes '?'.
/// nullopt only if the image ends first.
std::optional<std::string> utf16At(const PEImage& image, std::uint64_t rva, std::size_t maxChars);

/// NUL-terminated 8-bit text at `rva` (at most `maxChars`), or nullopt if
/// it isn't terminated in range or contains non-printable bytes.
std::optional<std::string> asciiAt(const PEImage& image, std::uint64_t rva, std::size_t maxChars);

/// The text of a UNICODE_STRING {Length, MaximumLength, Buffer} stored at
/// `rva` with a Buffer pointing into the image (RTL_CONSTANT_STRING /
/// DECLARE_CONST_UNICODE_STRING), or nullopt.
std::optional<std::string> unicodeStringAt(const PEImage& image, std::uint64_t rva);

/// The GUID at `rva` as {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}, or empty.
std::string guidAt(const PEImage& image, std::uint64_t rva);

} // namespace dasa::core::pe
