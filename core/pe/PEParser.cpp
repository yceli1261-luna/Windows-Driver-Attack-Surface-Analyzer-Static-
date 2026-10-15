#include "core/pe/PEParser.h"

#include <array>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iterator>
#include <mutex>
#include <utility>

#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <spdlog/spdlog.h>

namespace dasa::core::pe {

namespace {

using FlagTable = std::initializer_list<std::pair<std::uint32_t, const char*>>;

// Flag/name tables carried over from the v1 Python parser so the two
// versions report the same names for the same bits.
constexpr FlagTable kFileCharacteristics = {
    {0x0001, "RELOCS_STRIPPED"},      {0x0002, "EXECUTABLE_IMAGE"},
    {0x0004, "LINE_NUMS_STRIPPED"},   {0x0008, "LOCAL_SYMS_STRIPPED"},
    {0x0010, "AGGRESSIVE_WS_TRIM"},   {0x0020, "LARGE_ADDRESS_AWARE"},
    {0x0080, "BYTES_REVERSED_LO"},    {0x0100, "32BIT_MACHINE"},
    {0x0200, "DEBUG_STRIPPED"},       {0x0400, "REMOVABLE_RUN_FROM_SWAP"},
    {0x0800, "NET_RUN_FROM_SWAP"},    {0x1000, "SYSTEM"},
    {0x2000, "DLL"},                  {0x4000, "UP_SYSTEM_ONLY"},
    {0x8000, "BYTES_REVERSED_HI"},
};

constexpr FlagTable kDllCharacteristics = {
    {0x0020, "HIGH_ENTROPY_VA"}, {0x0040, "DYNAMIC_BASE"},
    {0x0080, "FORCE_INTEGRITY"}, {0x0100, "NX_COMPAT"},
    {0x0200, "NO_ISOLATION"},    {0x0400, "NO_SEH"},
    {0x0800, "NO_BIND"},         {0x1000, "APPCONTAINER"},
    {0x2000, "WDM_DRIVER"},      {0x4000, "GUARD_CF"},
    {0x8000, "TERMINAL_SERVER_AWARE"},
};

// IMAGE_SCN_* values from winnt.h. (v1's table had several of these bits
// shifted - e.g. it reported 0x02000000, MEM_DISCARDABLE, as EXECUTE - so
// this one follows the header rather than the Python port.)
constexpr FlagTable kSectionCharacteristics = {
    {0x00000020, "CODE"},
    {0x00000040, "INITIALIZED_DATA"},
    {0x00000080, "UNINITIALIZED_DATA"},
    {0x00000200, "INFO"},
    {0x00000800, "REMOVE"},
    {0x00001000, "COMDAT"},
    {0x00008000, "GPREL"},
    {0x01000000, "NRELOC_OVFL"},
    {0x02000000, "DISCARDABLE"},
    {0x04000000, "NOT_CACHED"},
    {0x08000000, "NOT_PAGED"},
    {0x10000000, "SHARED"},
    {0x20000000, "EXECUTE"},
    {0x40000000, "READ"},
    {0x80000000, "WRITE"},
};

std::vector<std::string> flagsFor(std::uint32_t value, FlagTable table) {
    std::vector<std::string> out;
    for (const auto& [mask, name] : table) {
        if ((value & mask) != 0) {
            out.emplace_back(name);
        }
    }
    return out;
}

std::string machineName(std::uint16_t machine) {
    switch (machine) {
    case 0x014C: return "x86";
    case 0x0200: return "Intel Itanium";
    case 0x8664: return "x64";
    case 0x01C0: return "ARM";
    case 0x01C4: return "ARM (Thumb-2)";
    case 0xAA64: return "ARM64";
    case 0x5032: return "RISC-V 32";
    case 0x5064: return "RISC-V 64";
    default: {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "UNKNOWN_0x%04X", machine);
        return buf;
    }
    }
}

std::string subsystemName(std::uint16_t subsystem) {
    switch (subsystem) {
    case 0: return "UNKNOWN";
    case 1: return "NATIVE";
    case 2: return "WINDOWS_GUI";
    case 3: return "WINDOWS_CUI";
    case 5: return "OS2_CUI";
    case 7: return "POSIX_CUI";
    case 8: return "NATIVE_WINDOWS";
    case 9: return "WINDOWS_CE_GUI";
    case 10: return "EFI_APPLICATION";
    case 11: return "EFI_BOOT_SERVICE_DRIVER";
    case 12: return "EFI_RUNTIME_DRIVER";
    case 13: return "EFI_ROM";
    case 14: return "XBOX";
    case 16: return "WINDOWS_BOOT_APPLICATION";
    default: return "UNKNOWN_" + std::to_string(subsystem);
    }
}

std::string toHex(const std::uint8_t* data, std::size_t size) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

std::string formatUtc(std::time_t t) {
    std::tm tm{};
#ifdef _WIN32
    if (gmtime_s(&tm, &t) != 0) {
        return {};
    }
#else
    if (gmtime_r(&t, &tm) == nullptr) {
        return {};
    }
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
    return buf;
}

std::string formatDate(const std::array<std::int32_t, 6>& d) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d UTC", d[0], d[1], d[2], d[3],
                  d[4], d[5]);
    return buf;
}

std::string verificationText(LIEF::PE::Signature::VERIFICATION_FLAGS flags) {
    using Flags = LIEF::PE::Signature::VERIFICATION_FLAGS;
    const auto bits = static_cast<std::uint32_t>(flags);
    if (bits == 0) {
        return "OK";
    }
    std::string out;
    for (std::uint32_t bit = 1; bit != 0 && bit <= bits; bit <<= 1) {
        if ((bits & bit) != 0) {
            if (!out.empty()) {
                out += " | ";
            }
            out += LIEF::PE::Signature::flag_to_string(static_cast<Flags>(bit));
        }
    }
    return out;
}

std::vector<std::uint8_t> readFile(const std::filesystem::path& path) {
    // Read through std::filesystem::path rather than handing LIEF a narrow
    // string, so paths outside the ANSI code page still open on Windows.
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw PEParseError("Cannot open file: " + path.string());
    }
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
    if (in.bad()) {
        throw PEParseError("Error reading file: " + path.string());
    }
    return data;
}

void silenceLiefLogging() {
    // LIEF logs parser warnings to stderr by default; DASA reports problems
    // through its own logger and the parse result instead.
    static std::once_flag once;
    std::call_once(once, [] { LIEF::logging::disable(); });
}

SignatureInfo collectSignature(const LIEF::PE::Binary& binary) {
    SignatureInfo info;
    if (const auto* dir = binary.data_directory(LIEF::PE::DataDirectory::TYPES::CERTIFICATE_TABLE)) {
        // For the security directory the "RVA" field is a file offset.
        info.securityDirectoryOffset = dir->RVA();
        info.securityDirectorySize = dir->size();
    }
    info.hasEmbeddedSignature = info.securityDirectoryOffset != 0 && info.securityDirectorySize != 0;

    if (!binary.has_signatures()) {
        info.verification = info.hasEmbeddedSignature ? "Security directory present but no "
                                                        "parsable PKCS#7 signature"
                                                      : "No embedded signature";
        return info;
    }

    const auto flags = binary.verify_signature();
    info.digestValid = flags == LIEF::PE::Signature::VERIFICATION_FLAGS::OK;
    info.verification = verificationText(flags);

    for (const LIEF::PE::Signature& sig : binary.signatures()) {
        for (const LIEF::PE::x509& cert : sig.certificates()) {
            info.certificateSubjects.push_back(cert.subject());
        }
        for (const LIEF::PE::SignerInfo& signerInfo : sig.signers()) {
            Signer signer;
            signer.issuer = signerInfo.issuer();
            const auto serial = signerInfo.serial_number();
            signer.serialNumber = toHex(serial.data(), serial.size());
            signer.digestAlgorithm = LIEF::PE::to_string(signerInfo.digest_algorithm());
            if (const LIEF::PE::x509* cert = signerInfo.cert()) {
                signer.subject = cert->subject();
            }
            if (const auto* attr =
                    signerInfo.get_attribute(LIEF::PE::Attribute::TYPE::PKCS9_SIGNING_TIME)) {
                const auto& time = static_cast<const LIEF::PE::PKCS9SigningTime*>(attr)->time();
                signer.signingTime = formatDate(time);
            }
            info.signers.push_back(std::move(signer));
        }
    }
    return info;
}

} // namespace

std::size_t PEImage::importedFunctionCount() const {
    std::size_t n = 0;
    for (const auto& lib : imports) {
        n += lib.functions.size();
    }
    return n;
}

FileHashes computeHashes(std::span<const std::uint8_t> data) {
    std::array<unsigned char, 16> md5{};
    std::array<unsigned char, 20> sha1{};
    std::array<unsigned char, 32> sha256{};
    if (mbedtls_md5(data.data(), data.size(), md5.data()) != 0 ||
        mbedtls_sha1(data.data(), data.size(), sha1.data()) != 0 ||
        mbedtls_sha256(data.data(), data.size(), sha256.data(), /*is224=*/0) != 0) {
        throw PEParseError("Hash computation failed");
    }
    return {toHex(md5.data(), md5.size()), toHex(sha1.data(), sha1.size()),
            toHex(sha256.data(), sha256.size())};
}

PEImage parsePE(const std::filesystem::path& path) {
    silenceLiefLogging();

    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        throw PEParseError("File not found: " + path.string());
    }

    std::vector<std::uint8_t> data = readFile(path);

    PEImage image;
    image.path = path;
    image.fileName = path.filename().string();
    image.fileSize = data.size();
    image.hashes = computeHashes(data);

    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(std::move(data));
    if (!binary) {
        throw PEParseError("Not a valid PE file: " + path.string());
    }

    const auto& header = binary->header();
    const auto& opt = binary->optional_header();

    image.machine = static_cast<std::uint16_t>(header.machine());
    image.machineName = machineName(image.machine);
    image.is64Bit = opt.magic() == LIEF::PE::PE_TYPE::PE32_PLUS;
    image.subsystem = static_cast<std::uint16_t>(opt.subsystem());
    image.subsystemName = subsystemName(image.subsystem);

    image.imageBase = opt.imagebase();
    image.sizeOfImage = opt.sizeof_image();
    image.sizeOfHeaders = opt.sizeof_headers();
    image.entryPointRva = opt.addressof_entrypoint();
    image.sectionAlignment = opt.section_alignment();
    image.fileAlignment = opt.file_alignment();

    image.timestamp = header.time_date_stamp();
    if (image.timestamp != 0) {
        image.timestampUtc = formatUtc(static_cast<std::time_t>(image.timestamp));
    }

    image.headerChecksum = opt.checksum();
    image.computedChecksum = binary->compute_checksum();

    image.fileCharacteristics = static_cast<std::uint16_t>(header.characteristics());
    image.fileCharacteristicFlags = flagsFor(image.fileCharacteristics, kFileCharacteristics);
    image.dllCharacteristics = static_cast<std::uint16_t>(opt.dll_characteristics());
    image.dllCharacteristicFlags = flagsFor(image.dllCharacteristics, kDllCharacteristics);

    image.linkerMajor = opt.major_linker_version();
    image.linkerMinor = opt.minor_linker_version();
    image.osMajor = opt.major_operating_system_version();
    image.osMinor = opt.minor_operating_system_version();
    image.subsystemMajor = opt.major_subsystem_version();
    image.subsystemMinor = opt.minor_subsystem_version();

    if (const LIEF::PE::CodeViewPDB* pdb = binary->codeview_pdb()) {
        image.pdbPath = pdb->filename();
    }

    for (const LIEF::PE::Section& s : binary->sections()) {
        Section section;
        section.name = s.name();
        section.virtualAddress = static_cast<std::uint32_t>(s.virtual_address());
        section.virtualSize = s.virtual_size();
        section.rawOffset = s.pointerto_raw_data();
        section.rawSize = s.sizeof_raw_data();
        section.characteristics = s.characteristics();
        section.flags = flagsFor(section.characteristics, kSectionCharacteristics);
        section.entropy = s.entropy();
        image.sections.push_back(std::move(section));
    }

    for (const LIEF::PE::Import& imp : binary->imports()) {
        ImportedLibrary lib;
        lib.name = imp.name();
        for (const LIEF::PE::ImportEntry& entry : imp.entries()) {
            ImportedFunction fn;
            if (entry.is_ordinal()) {
                fn.ordinal = entry.ordinal();
            } else {
                fn.name = entry.name();
                fn.hint = entry.hint();
            }
            fn.iatRva = entry.iat_address();
            lib.functions.push_back(std::move(fn));
        }
        image.imports.push_back(std::move(lib));
    }

    if (const LIEF::PE::Export* exp = binary->get_export()) {
        for (const LIEF::PE::ExportEntry& entry : exp->entries()) {
            ExportedFunction fn;
            fn.name = entry.name();
            fn.rva = entry.address();
            fn.ordinal = entry.ordinal();
            if (entry.is_forwarded()) {
                const auto fwd = entry.forward_information();
                fn.forwarder = fwd.library + "." + fwd.function;
            }
            image.exports.push_back(std::move(fn));
        }
    }

    image.signature = collectSignature(*binary);

    spdlog::info("Parsed {}: {} {}, {} sections, {} imports from {} libraries, {} exports, "
                 "embedded signature: {}",
                 image.fileName, image.machineName, image.subsystemName, image.sections.size(),
                 image.importedFunctionCount(), image.imports.size(), image.exports.size(),
                 image.signature.hasEmbeddedSignature ? image.signature.verification : "none");
    return image;
}

} // namespace dasa::core::pe
