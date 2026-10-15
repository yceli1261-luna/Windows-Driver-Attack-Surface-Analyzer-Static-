#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace dasa::core::pe {

// Value types describing a parsed PE image. Deliberately plain structs with
// no LIEF types in them: the parser is the only place that knows about LIEF,
// so the rest of core/ and the UI can consume these without pulling it in.

struct FileHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

struct Section {
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t characteristics = 0;
    std::vector<std::string> flags; // e.g. CODE, EXECUTE, READ, WRITE
    double entropy = 0.0;

    bool isExecutable() const { return (characteristics & 0x20000000u) != 0; }
    bool isWritable() const { return (characteristics & 0x80000000u) != 0; }
};

struct ImportedFunction {
    std::string name;                    // empty when imported by ordinal only
    std::optional<std::uint16_t> ordinal; // set when imported by ordinal
    std::uint16_t hint = 0;
    std::uint64_t iatRva = 0;
};

struct ImportedLibrary {
    std::string name;
    std::vector<ImportedFunction> functions;
};

struct ExportedFunction {
    std::string name;
    std::uint32_t rva = 0;
    std::uint16_t ordinal = 0;
    std::string forwarder; // "LIB.Function" when forwarded, otherwise empty
};

struct Signer {
    std::string subject;
    std::string issuer;
    std::string serialNumber;    // hex
    std::string digestAlgorithm; // e.g. SHA_256
    std::string signingTime;     // "YYYY-MM-DD HH:MM:SS UTC", empty if absent
};

struct SignatureInfo {
    // IMAGE_DIRECTORY_ENTRY_SECURITY present and non-empty. Inbox Windows
    // drivers are often catalog-signed instead, so false here does not mean
    // "unsigned" in the Windows sense - only that nothing is embedded.
    bool hasEmbeddedSignature = false;
    std::uint32_t securityDirectoryOffset = 0;
    std::uint32_t securityDirectorySize = 0;

    // Authenticode check: the PKCS#7 structure is consistent and its digest
    // matches the file. This is not a chain-of-trust check against the
    // Windows root store.
    bool digestValid = false;
    std::string verification; // "OK" or the failure flags

    std::vector<Signer> signers;
    std::vector<std::string> certificateSubjects; // every cert in the blob
};

// One RUNTIME_FUNCTION entry from the x64 exception directory (.pdata).
// Compilers emit one for every non-leaf function, which makes the table
// the most reliable source of function starts on x64. A function whose
// body is split (e.g. cold code moved away) has extra "chained" entries
// whose unwind info points back at the primary entry.
struct RuntimeFunction {
    std::uint32_t begin = 0;        // RVA
    std::uint32_t end = 0;          // RVA, exclusive
    std::uint32_t unwindInfo = 0;   // RVA of UNWIND_INFO
    std::uint32_t primaryBegin = 0; // begin of the non-chained root entry

    bool isChained() const { return primaryBegin != begin; }
};

struct PEImage {
    std::filesystem::path path;
    std::string fileName;
    std::uint64_t fileSize = 0;
    FileHashes hashes;

    bool is64Bit = false;
    std::uint16_t machine = 0;
    std::string machineName;
    std::uint16_t subsystem = 0;
    std::string subsystemName;

    std::uint64_t imageBase = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::uint32_t entryPointRva = 0;
    std::uint32_t sectionAlignment = 0;
    std::uint32_t fileAlignment = 0;

    std::uint32_t timestamp = 0;
    std::string timestampUtc; // empty when timestamp is 0

    std::uint32_t headerChecksum = 0;   // as stored in the optional header
    std::uint32_t computedChecksum = 0; // recomputed over the file

    std::uint16_t fileCharacteristics = 0;
    std::vector<std::string> fileCharacteristicFlags;
    std::uint16_t dllCharacteristics = 0;
    std::vector<std::string> dllCharacteristicFlags;

    std::uint8_t linkerMajor = 0;
    std::uint8_t linkerMinor = 0;
    std::uint16_t osMajor = 0;
    std::uint16_t osMinor = 0;
    std::uint16_t subsystemMajor = 0;
    std::uint16_t subsystemMinor = 0;

    std::string pdbPath; // from the CodeView debug entry, if any

    std::vector<Section> sections;
    std::vector<ImportedLibrary> imports;
    std::vector<ExportedFunction> exports;
    SignatureInfo signature;
    std::vector<RuntimeFunction> runtimeFunctions; // x64 .pdata, sorted by begin

    // The image as the loader would lay it out: headers and each section's
    // raw data copied to its RVA, zero-filled elsewhere (sizeOfImage bytes).
    // Shared so copies of a PEImage don't duplicate it.
    std::shared_ptr<const std::vector<std::uint8_t>> mappedImage;

    std::uint64_t entryPointVa() const { return entryPointRva ? imageBase + entryPointRva : 0; }
    std::size_t importedFunctionCount() const;
    bool checksumMatches() const { return headerChecksum == computedChecksum; }

    /// Bytes from `rva` to the end of the mapped image (empty if out of range).
    std::span<const std::uint8_t> bytesAt(std::uint64_t rva) const;
    const Section* sectionContaining(std::uint64_t rva) const;
    bool isExecutable(std::uint64_t rva) const;
    /// Converts a virtual address to an RVA if it falls inside the image.
    std::optional<std::uint64_t> vaToRva(std::uint64_t va) const;
};

} // namespace dasa::core::pe
