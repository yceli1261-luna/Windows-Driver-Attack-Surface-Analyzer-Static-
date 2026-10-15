#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <string>

#include "core/pe/PEParser.h"

// Expected values for the two fixture drivers were taken from pefile
// 2024.8.26 (the parser v1 used), not from this parser's own output, so the
// tests check LIEF-backed parsing against an independent implementation.
// The fixtures are the synthetic drivers built by the v1 repo's
// samples/_build_sample.py and _build_risky_sample.py.

namespace fs = std::filesystem;
using namespace dasa::core::pe;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

const ImportedLibrary* findLibrary(const PEImage& image, const std::string& name) {
    for (const auto& lib : image.imports) {
        if (lib.name == name) {
            return &lib;
        }
    }
    return nullptr;
}

bool hasFlag(const std::vector<std::string>& flags, const char* flag) {
    return std::find(flags.begin(), flags.end(), flag) != flags.end();
}

} // namespace

TEST(Hashes, KnownVectors) {
    const std::string abc = "abc";
    const auto hashes = computeHashes(
        {reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()});
    EXPECT_EQ(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
    EXPECT_EQ(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT_EQ(hashes.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(PEParser, RiskyDriverHeaders) {
    const PEImage image = parsePE(fixture("DASARiskyDriver.sys"));

    EXPECT_EQ(image.fileName, "DASARiskyDriver.sys");
    EXPECT_EQ(image.fileSize, 49664u);
    EXPECT_EQ(image.hashes.md5, "767f6f16829e8e1d8089eb3dcf76df6e");
    EXPECT_EQ(image.hashes.sha1, "c3da12d02431836264a38d2a984567cc24cdc70f");
    EXPECT_EQ(image.hashes.sha256,
              "91527571262c53c37398445278fe230c2ef94b7fe020cbb5a44c5aa51befea9c");

    EXPECT_TRUE(image.is64Bit);
    EXPECT_EQ(image.machine, 0x8664);
    EXPECT_EQ(image.machineName, "x64");
    EXPECT_EQ(image.subsystem, 1);
    EXPECT_EQ(image.subsystemName, "NATIVE");
    EXPECT_EQ(image.imageBase, 0x7ff6e4b00000ull);
    EXPECT_EQ(image.sizeOfImage, 0xd000u);
    EXPECT_EQ(image.entryPointRva, 0x1000u);
    EXPECT_EQ(image.entryPointVa(), 0x7ff6e4b01000ull);
    EXPECT_EQ(image.timestamp, 1725053540u);
    EXPECT_EQ(image.timestampUtc, "2024-08-30 21:32:20 UTC");
    EXPECT_EQ(image.linkerMajor, 14);
    EXPECT_EQ(image.linkerMinor, 0);

    EXPECT_EQ(image.headerChecksum, 0u);
    EXPECT_EQ(image.computedChecksum, 0x19ff4u);
    EXPECT_FALSE(image.checksumMatches());

    EXPECT_EQ(image.fileCharacteristics, 0x2022);
    EXPECT_TRUE(hasFlag(image.fileCharacteristicFlags, "EXECUTABLE_IMAGE"));
    EXPECT_TRUE(hasFlag(image.fileCharacteristicFlags, "LARGE_ADDRESS_AWARE"));
    EXPECT_TRUE(hasFlag(image.fileCharacteristicFlags, "DLL"));
    EXPECT_EQ(image.dllCharacteristics, 0);
    EXPECT_TRUE(image.dllCharacteristicFlags.empty());
    EXPECT_TRUE(image.pdbPath.empty());
}

TEST(PEParser, RiskyDriverSections) {
    const PEImage image = parsePE(fixture("DASARiskyDriver.sys"));

    struct Expected {
        const char* name;
        std::uint32_t va, vsize, rawOffset, rawSize, characteristics;
        double entropy;
    };
    const Expected expected[] = {
        {".text", 0x1000, 0x9000, 0x200, 0x9000, 0x60000020, 0.1626},
        {".rdata", 0xa000, 0x2000, 0x9200, 0x2000, 0x40000040, 1.6471},
        {".data", 0xc000, 0x1000, 0xb200, 0x1000, 0xc0000040, 0.0},
    };
    ASSERT_EQ(image.sections.size(), std::size(expected));
    for (std::size_t i = 0; i < std::size(expected); ++i) {
        const Section& s = image.sections[i];
        const Expected& e = expected[i];
        SCOPED_TRACE(e.name);
        EXPECT_EQ(s.name, e.name);
        EXPECT_EQ(s.virtualAddress, e.va);
        EXPECT_EQ(s.virtualSize, e.vsize);
        EXPECT_EQ(s.rawOffset, e.rawOffset);
        EXPECT_EQ(s.rawSize, e.rawSize);
        EXPECT_EQ(s.characteristics, e.characteristics);
        EXPECT_NEAR(s.entropy, e.entropy, 1e-3);
    }

    const Section& text = image.sections[0];
    EXPECT_TRUE(text.isExecutable());
    EXPECT_FALSE(text.isWritable());
    EXPECT_TRUE(hasFlag(text.flags, "CODE"));
    EXPECT_TRUE(hasFlag(text.flags, "EXECUTE"));
    EXPECT_TRUE(hasFlag(text.flags, "READ"));
    EXPECT_FALSE(hasFlag(text.flags, "DISCARDABLE"));

    const Section& data = image.sections[2];
    EXPECT_FALSE(data.isExecutable());
    EXPECT_TRUE(data.isWritable());
    EXPECT_TRUE(hasFlag(data.flags, "WRITE"));
}

TEST(PEParser, RiskyDriverImports) {
    const PEImage image = parsePE(fixture("DASARiskyDriver.sys"));

    ASSERT_EQ(image.imports.size(), 2u);
    EXPECT_EQ(image.importedFunctionCount(), 33u);

    const ImportedLibrary* ntos = findLibrary(image, "ntoskrnl.exe");
    ASSERT_NE(ntos, nullptr);
    ASSERT_EQ(ntos->functions.size(), 30u);
    EXPECT_EQ(ntos->functions[0].name, "IoCreateDevice");
    EXPECT_EQ(ntos->functions[1].name, "IoCreateSymbolicLink");
    EXPECT_EQ(ntos->functions[2].name, "IoDeleteDevice");
    EXPECT_FALSE(ntos->functions[0].ordinal.has_value());
    EXPECT_EQ(ntos->functions[0].iatRva, 0xb154u);

    const ImportedLibrary* hal = findLibrary(image, "HAL.dll");
    ASSERT_NE(hal, nullptr);
    ASSERT_EQ(hal->functions.size(), 3u);
    EXPECT_EQ(hal->functions[0].name, "HalSetBusDataByOffset");
    EXPECT_EQ(hal->functions[1].name, "HalGetBusDataByOffset");
    EXPECT_EQ(hal->functions[2].name, "KeStallExecutionProcessor");
    EXPECT_EQ(hal->functions[0].iatRva, 0xb24cu);

    EXPECT_TRUE(image.exports.empty());
}

TEST(PEParser, UnsignedDriverHasNoSignature) {
    const PEImage image = parsePE(fixture("DASARiskyDriver.sys"));
    EXPECT_FALSE(image.signature.hasEmbeddedSignature);
    EXPECT_FALSE(image.signature.digestValid);
    EXPECT_EQ(image.signature.securityDirectorySize, 0u);
    EXPECT_TRUE(image.signature.signers.empty());
}

TEST(PEParser, SampleDriverWithoutImports) {
    const PEImage image = parsePE(fixture("DASASampleDriver.sys"));

    EXPECT_EQ(image.fileSize, 45568u);
    EXPECT_EQ(image.hashes.sha256,
              "c2833d6bf8f377cfe9ff0b9b2a67412a7b50ce09b31e5e8e65998d7136885077");
    EXPECT_EQ(image.sizeOfImage, 0xc000u);
    EXPECT_EQ(image.computedChecksum, 0xc9b8u);
    EXPECT_EQ(image.dllCharacteristics, 0x1c0);
    EXPECT_TRUE(hasFlag(image.dllCharacteristicFlags, "DYNAMIC_BASE"));
    EXPECT_TRUE(hasFlag(image.dllCharacteristicFlags, "FORCE_INTEGRITY"));
    EXPECT_TRUE(hasFlag(image.dllCharacteristicFlags, "NX_COMPAT"));
    EXPECT_EQ(image.dllCharacteristicFlags.size(), 3u);

    ASSERT_EQ(image.sections.size(), 3u);
    EXPECT_EQ(image.sections[1].name, ".rdata");
    EXPECT_NEAR(image.sections[1].entropy, 1.2036, 1e-3);
    EXPECT_TRUE(image.imports.empty());
    EXPECT_TRUE(image.exports.empty());
}

TEST(PEParser, MissingFileThrows) {
    EXPECT_THROW(parsePE(fixture("does_not_exist.sys")), PEParseError);
}

TEST(PEParser, NonPeFileThrows) {
    const fs::path path = fs::temp_directory_path() / "dasa_not_a_pe.sys";
    {
        std::ofstream out(path, std::ios::binary);
        out << "This is plain text, not a PE image.";
    }
    EXPECT_THROW(parsePE(path), PEParseError);
    fs::remove(path);
}

// A real, embedded-signed Microsoft driver from the machine running the
// tests. Values that vary between Windows builds (export count, checksum)
// are checked for consistency rather than pinned.
TEST(PEParser, SignedSystemDriver) {
    const fs::path cng = "C:/Windows/System32/drivers/cng.sys";
    if (!fs::exists(cng)) {
        GTEST_SKIP() << "cng.sys not present on this machine";
    }
    const PEImage image = parsePE(cng);

    EXPECT_EQ(image.machineName, "x64");
    EXPECT_EQ(image.subsystemName, "NATIVE");
    EXPECT_TRUE(image.checksumMatches());
    EXPECT_NE(findLibrary(image, "ntoskrnl.exe"), nullptr);

    ASSERT_FALSE(image.exports.empty());
    const bool exportsBCrypt =
        std::any_of(image.exports.begin(), image.exports.end(),
                    [](const ExportedFunction& e) { return e.name == "BCryptCreateHash"; });
    EXPECT_TRUE(exportsBCrypt);

    const SignatureInfo& sig = image.signature;
    EXPECT_TRUE(sig.hasEmbeddedSignature);
    EXPECT_GT(sig.securityDirectorySize, 0u);
    EXPECT_TRUE(sig.digestValid) << sig.verification;
    ASSERT_FALSE(sig.signers.empty());
    EXPECT_NE(sig.signers[0].subject.find("Microsoft"), std::string::npos) << sig.signers[0].subject;
    EXPECT_FALSE(sig.signers[0].serialNumber.empty());
    EXPECT_FALSE(sig.certificateSubjects.empty());
}
