#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>

#include "core/pe/PEImage.h"

namespace dasa::core::pe {

class PEParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Parses a PE file (LIEF-backed) into a PEImage: headers, sections,
/// imports, exports, embedded Authenticode signature and file hashes.
/// Throws PEParseError if the file can't be read or isn't a valid PE.
/// Safe to call from any thread; holds no shared state.
PEImage parsePE(const std::filesystem::path& path);

/// MD5/SHA1/SHA256 of a byte buffer, lowercase hex.
FileHashes computeHashes(std::span<const std::uint8_t> data);

} // namespace dasa::core::pe
