#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <string>

#include "core/driver/DeviceObjects.h"
#include "core/driver/DriverAnalyzer.h"
#include "core/ioctl/IoctlExtractor.h"
#include "core/pe/PEParser.h"

// IOCTL and device-object recovery (Phase 5). Expected values come from the
// fixture generators (tests/fixtures/drivers/gen_wdm_fixture.py,
// gen_kmdf_fixture.py, v1's samples/_build_risky_sample.py), from the
// CTL_CODE layout in devioctl.h and from Microsoft's documentation of
// beep.sys's IOCTL_BEEP_SET (ntddbeep.h) - not from DASA output.

namespace fs = std::filesystem;
using namespace dasa::core;
using ioctl::IoctlEvidence;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

struct Analysis {
    driver::DriverAnalysis driver;
    ioctl::IoctlAnalysis ioctls;
    driver::DeviceAnalysis devices;
};

Analysis analyze(const fs::path& path) {
    const pe::PEImage image = pe::parsePE(path);
    const auto functions = functions::discoverFunctions(image);
    Analysis a;
    a.driver = driver::analyzeDriver(image, functions);
    a.ioctls = ioctl::extractIoctls(image, functions, a.driver);
    a.devices = driver::analyzeDevices(image, functions, a.driver);
    return a;
}

std::map<std::uint32_t, const ioctl::ExtractedIoctl*> byCode(const ioctl::IoctlAnalysis& io) {
    std::map<std::uint32_t, const ioctl::ExtractedIoctl*> m;
    for (const auto& e : io.ioctls) {
        m[e.decoded.code] = &e;
    }
    return m;
}

} // namespace

TEST(IoctlCodec, DecodesCtlCodeFields) {
    // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
    const auto d = ioctl::decodeIoctl(0x0022200B);
    EXPECT_EQ(d.deviceType, 0x22u);
    EXPECT_EQ(d.function, 0x802u);
    EXPECT_EQ(d.method, ioctl::kMethodNeither);
    EXPECT_EQ(d.access, ioctl::kFileAnyAccess);
    EXPECT_TRUE(d.isMethodNeither());
    EXPECT_TRUE(d.isAnyAccess());
    EXPECT_TRUE(d.isCustomFunction());
    EXPECT_EQ(ioctl::ctlCode(0x22, 0x802, 3, 0), 0x0022200Bu);

    // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)
    const auto w = ioctl::decodeIoctl(0x0022A059);
    EXPECT_EQ(w.function, 0x816u);
    EXPECT_EQ(w.method, ioctl::kMethodInDirect);
    EXPECT_EQ(w.access, 2u);

    EXPECT_EQ(ioctl::deviceTypeName(0x22), "FILE_DEVICE_UNKNOWN");
    EXPECT_EQ(ioctl::deviceTypeName(0x8001), "0x8001 (vendor)");
    EXPECT_STREQ(ioctl::methodName(3), "METHOD_NEITHER");
    EXPECT_STREQ(ioctl::accessName(0), "FILE_ANY_ACCESS");
    EXPECT_EQ(ioctl::hexCode(0x22200B), "0x0022200B");
}

TEST(IoctlCodec, IoctlShapeFilter) {
    EXPECT_TRUE(ioctl::looksLikeIoctl(0x00222000, false));
    EXPECT_FALSE(ioctl::looksLikeIoctl(0x00222000, true)); // Microsoft device type
    EXPECT_TRUE(ioctl::looksLikeIoctl(0x80002000, true));  // vendor device type
    EXPECT_FALSE(ioctl::looksLikeIoctl(0x0000FFFF, false)); // device type 0
    EXPECT_FALSE(ioctl::looksLikeIoctl(0xCCCCCCCC, false)); // fill pattern
}

// DASAWdmSample.sys: tracked IoControlCode through a sub chain, a helper
// that receives the code, and a jump-table range; the InputBufferLength
// decoy (0x10000) must not be reported.
TEST(AttackSurface, WdmFixtureIoctls) {
    const Analysis a = analyze(fixture("DASAWdmSample.sys"));
    ASSERT_EQ(a.ioctls.anchors.size(), 1u);
    EXPECT_EQ(a.ioctls.anchors[0], "IRP_MJ_DEVICE_CONTROL");

    const auto codes = byCode(a.ioctls);
    const std::set<std::uint32_t> expected{0x00222000, 0x00222004, 0x00222008, 0x0022E00B};
    std::set<std::uint32_t> actual;
    for (const auto& [code, e] : codes) {
        actual.insert(code);
        EXPECT_EQ(e->evidence, IoctlEvidence::TrackedCompare) << ioctl::hexCode(code);
        EXPECT_EQ(e->handlerFunction, 0x1200u);
    }
    EXPECT_EQ(actual, expected);

    EXPECT_EQ(codes.at(0x00222000)->caseTarget.value_or(0), 0x1260u);
    EXPECT_EQ(codes.at(0x00222004)->caseTarget.value_or(0), 0x1270u);
    EXPECT_EQ(codes.at(0x00222008)->caseTarget.value_or(0), 0x1280u);
    EXPECT_EQ(codes.at(0x00222000)->comparedIn, 0x1200u);
    // Found in the helper the code was passed to.
    EXPECT_EQ(codes.at(0x0022E00B)->comparedIn, 0x1300u);
    EXPECT_EQ(codes.at(0x0022E00B)->caseTarget.value_or(0), 0x1312u);
    EXPECT_TRUE(codes.at(0x0022E00B)->decoded.isMethodNeither());
    EXPECT_EQ(codes.at(0x0022E00B)->decoded.access, 3u);

    ASSERT_EQ(a.ioctls.switchRanges.size(), 1u);
    EXPECT_EQ(a.ioctls.switchRanges[0].low, 0x00222008u);
    EXPECT_EQ(a.ioctls.switchRanges[0].high, 0x00222028u);
    EXPECT_EQ(a.ioctls.switchRanges[0].inFunction, 0x1200u);
}

TEST(AttackSurface, WdmFixtureDevices) {
    const Analysis a = analyze(fixture("DASAWdmSample.sys"));
    ASSERT_EQ(a.devices.devices.size(), 1u);
    const auto& dev = a.devices.devices[0];
    EXPECT_EQ(dev.api, "IoCreateDevice");
    EXPECT_TRUE(dev.nameResolved);
    EXPECT_EQ(dev.name, "\\Device\\DasaWdm");
    EXPECT_EQ(dev.deviceType.value_or(0), 0x22u);
    EXPECT_EQ(dev.characteristics.value_or(0xFFFFFFFF), 0u);
    EXPECT_EQ(dev.secureOpen(), std::optional<bool>(false));
    EXPECT_EQ(dev.exclusive, std::optional<bool>(false));
    EXPECT_EQ(dev.inFunction, 0x1000u);

    ASSERT_EQ(a.devices.symbolicLinks.size(), 1u);
    EXPECT_EQ(a.devices.symbolicLinks[0].api, "IoCreateSymbolicLink");
    EXPECT_EQ(a.devices.symbolicLinks[0].link, "\\DosDevices\\DasaWdm");
    EXPECT_EQ(a.devices.symbolicLinks[0].target, "\\Device\\DasaWdm");

    EXPECT_EQ(a.devices.deviceNameStrings, std::vector<std::string>{"\\Device\\DasaWdm"});
    EXPECT_EQ(a.devices.linkNameStrings, std::vector<std::string>{"\\DosDevices\\DasaWdm"});

    // Phase 4 view of the same driver.
    EXPECT_EQ(a.driver.model.kind, driver::ModelKind::Wdm);
    ASSERT_NE(a.driver.dispatchFor(0x0E), nullptr);
    EXPECT_EQ(a.driver.dispatchFor(0x0E)->handler, 0x1200u);
    EXPECT_EQ(a.driver.dispatchFor(0x00)->handler, 0x1400u);
    EXPECT_EQ(a.driver.dispatchFor(0x02)->handler, 0x1400u);
}

TEST(AttackSurface, KmdfFixtureIoctlsAndDevice) {
    const Analysis a = analyze(fixture("DASAKmdfSample.sys"));

    const auto codes = byCode(a.ioctls);
    ASSERT_EQ(codes.size(), 2u);
    ASSERT_EQ(codes.count(0x0022E004), 1u);
    ASSERT_EQ(codes.count(0x00222003), 1u);
    for (const auto& [code, e] : codes) {
        EXPECT_EQ(e->evidence, IoctlEvidence::TrackedCompare);
        EXPECT_EQ(e->handlerFunction, 0x1600u);
        EXPECT_EQ(e->handler, "EvtIoDeviceControl (queue 1)");
        EXPECT_EQ(e->caseTarget.value_or(0), 0x1628u);
    }

    ASSERT_EQ(a.devices.devices.size(), 1u);
    const auto& dev = a.devices.devices[0];
    EXPECT_EQ(dev.api, "WdfDeviceInitAssignName");
    EXPECT_EQ(dev.name, "\\Device\\DasaKmdf");
    EXPECT_EQ(dev.deviceType.value_or(0), 0x22u);
    EXPECT_EQ(dev.secureOpen(), std::optional<bool>(true));
    EXPECT_EQ(dev.inFunction, 0x1300u);

    ASSERT_EQ(a.devices.symbolicLinks.size(), 1u);
    EXPECT_EQ(a.devices.symbolicLinks[0].api, "WdfDeviceCreateSymbolicLink");
    EXPECT_EQ(a.devices.symbolicLinks[0].link, "\\DosDevices\\DasaKmdf");

    ASSERT_EQ(a.devices.interfaces.size(), 1u);
    EXPECT_EQ(a.devices.interfaces[0].guid, "{12345678-1234-5678-9ABC-DEF012345678}");
}

// DASARiskyDriver compares [rdx+8] (not the real IoControlCode location), so
// its codes can only be found as constants in the handler: all 24 from the
// generator's IOCTL_SPEC, and no device objects (it only has the strings).
TEST(AttackSurface, RiskyFixtureConstants) {
    const Analysis a = analyze(fixture("DASARiskyDriver.sys"));
    const auto codes = byCode(a.ioctls);

    // (function, method, access) from _build_risky_sample.py's IOCTL_SPEC.
    const std::uint32_t spec[][3] = {
        {0x800, 0, 0}, {0x801, 0, 0}, {0x802, 3, 0}, {0x803, 3, 0}, {0x804, 0, 0}, {0x805, 0, 0},
        {0x806, 0, 0}, {0x807, 0, 0}, {0x808, 0, 0}, {0x809, 0, 0}, {0x80A, 3, 0}, {0x80B, 3, 0},
        {0x80C, 0, 0}, {0x80D, 0, 0}, {0x80E, 0, 0}, {0x80F, 0, 0}, {0x810, 0, 0}, {0x811, 0, 0},
        {0x812, 0, 0}, {0x813, 2, 0}, {0x814, 0, 0}, {0x815, 0, 0}, {0x816, 1, 2}, {0x817, 0, 1},
    };
    ASSERT_EQ(codes.size(), std::size(spec));
    for (const auto& s : spec) {
        const std::uint32_t code = ioctl::ctlCode(0x22, s[0], s[1], s[2]);
        ASSERT_EQ(codes.count(code), 1u) << ioctl::hexCode(code);
        EXPECT_EQ(codes.at(code)->evidence, IoctlEvidence::HandlerConstant);
        EXPECT_EQ(codes.at(code)->handlerFunction, 0x5000u);
    }

    EXPECT_TRUE(a.devices.devices.empty());
    const std::set<std::string> devStrings(a.devices.deviceNameStrings.begin(), a.devices.deviceNameStrings.end());
    EXPECT_EQ(devStrings.count("\\Device\\DASAPhysMem"), 1u);
    EXPECT_EQ(devStrings.count("\\Device\\DASAMsr"), 1u);
    EXPECT_EQ(devStrings.count("\\Device\\PhysicalMemory"), 1u);
}

// beep.sys handles IOCTL_BEEP_SET = CTL_CODE(FILE_DEVICE_BEEP, 0,
// METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x00010000 (ntddbeep.h) and creates
// \Device\Beep.
TEST(AttackSurface, RealBeepDriver) {
    const fs::path beep = "C:/Windows/System32/drivers/beep.sys";
    if (!fs::exists(beep)) {
        GTEST_SKIP() << "beep.sys not present";
    }
    const Analysis a = analyze(beep);
    const auto codes = byCode(a.ioctls);
    ASSERT_EQ(codes.count(0x00010000), 1u);
    EXPECT_EQ(codes.at(0x00010000)->evidence, IoctlEvidence::TrackedCompare);

    ASSERT_FALSE(a.devices.devices.empty());
    EXPECT_EQ(a.devices.devices[0].name, "\\Device\\Beep");
    EXPECT_EQ(a.devices.devices[0].deviceType.value_or(0), 0x01u); // FILE_DEVICE_BEEP
}

// null.sys registers no IRP_MJ_DEVICE_CONTROL handler, so it has no IOCTLs
// of its own; it creates \Device\Null with FILE_DEVICE_SECURE_OPEN.
TEST(AttackSurface, RealNullDriver) {
    const fs::path null = "C:/Windows/System32/drivers/null.sys";
    if (!fs::exists(null)) {
        GTEST_SKIP() << "null.sys not present";
    }
    const Analysis a = analyze(null);
    EXPECT_TRUE(a.ioctls.anchors.empty());
    EXPECT_TRUE(a.ioctls.ioctls.empty());
    ASSERT_FALSE(a.devices.devices.empty());
    EXPECT_EQ(a.devices.devices[0].name, "\\Device\\Null");
    EXPECT_EQ(a.devices.devices[0].secureOpen(), std::optional<bool>(true));
}
