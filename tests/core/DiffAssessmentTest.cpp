#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <string>

#include "analysis/diff/AnalysisDiff.h"
#include "analysis/report/Assessment.h"
#include "analysis/static/StaticAnalysisPipeline.h"

// Diff and assessment (Phase 12). Expectations come from the two fixture
// generators: gen_wdm_fixture.py imports RtlInitUnicodeString,
// IoCreateDevice, IoCreateSymbolicLink, IofCompleteRequest, MmMapIoSpace,
// MmGetSystemRoutineAddress and creates \Device\DasaWdm; gen_taint_fixture.py
// imports RtlInitUnicodeString, IoCreateDevice, IoCreateSymbolicLink,
// MmMapIoSpace, memcpy, ProbeForRead and creates \Device\DasaTaint. Both
// have the same CreateClose body (xor eax, eax; ret) at different addresses
// (0x1400 and 0x1480).

namespace fs = std::filesystem;
using namespace dasa;
using analysis::FunctionChange;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

std::shared_ptr<const analysis::AnalysisResult> load(const char* name) {
    return analysis::runStaticAnalysis(fixture(name));
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

} // namespace

TEST(Diff, SameFileIsIdentical) {
    const auto a = load("DASAWdmSample.sys");
    const auto b = load("DASAWdmSample.sys");
    const auto d = analysis::diffAnalyses(*a, *b);
    EXPECT_TRUE(d.sameFile);
    EXPECT_EQ(d.identical, a->functions->functions.size());
    EXPECT_EQ(d.changed + d.added + d.removed, 0u);
    EXPECT_TRUE(d.imports.added.empty() && d.imports.removed.empty());
    EXPECT_TRUE(d.findings.added.empty() && d.findings.removed.empty());
}

TEST(Diff, WdmToTaintFixture) {
    const auto oldR = load("DASAWdmSample.sys");
    const auto newR = load("DASATaintSample.sys");
    const auto d = analysis::diffAnalyses(*oldR, *newR);
    EXPECT_FALSE(d.sameFile);

    std::vector<std::string> added = d.imports.added, removed = d.imports.removed;
    std::sort(added.begin(), added.end());
    std::sort(removed.begin(), removed.end());
    EXPECT_EQ(added, (std::vector<std::string>{"ntoskrnl.exe!ProbeForRead", "ntoskrnl.exe!memcpy"}));
    EXPECT_EQ(removed,
              (std::vector<std::string>{"ntoskrnl.exe!IofCompleteRequest", "ntoskrnl.exe!MmGetSystemRoutineAddress"}));

    EXPECT_TRUE(contains(d.devices.added, R"(\Device\DasaTaint)"));
    EXPECT_TRUE(contains(d.devices.added, R"(\DosDevices\DasaTaint)"));
    EXPECT_TRUE(contains(d.devices.removed, R"(\Device\DasaWdm)"));
    EXPECT_TRUE(std::any_of(d.ioctls.removed.begin(), d.ioctls.removed.end(),
                            [](const std::string& s) { return s.rfind("0x0022E00B", 0) == 0; }));
    EXPECT_TRUE(std::any_of(d.ioctls.added.begin(), d.ioctls.added.end(),
                            [](const std::string& s) { return s.rfind("0x00222010", 0) == 0; }));

    // CreateClose moved from 0x1400 to 0x1480 with the same code.
    const auto cc = std::find_if(d.functions.begin(), d.functions.end(),
                                 [](const auto& f) { return f.oldRva == 0x1400 && f.newRva == 0x1480; });
    ASSERT_NE(cc, d.functions.end());
    EXPECT_EQ(cc->change, FunctionChange::Identical);
    EXPECT_EQ(cc->matchedBy, "fingerprint");

    // Every function of each side is accounted for exactly once.
    EXPECT_EQ(d.identical + d.changed + d.removed, oldR->functions->functions.size());
    EXPECT_EQ(d.identical + d.changed + d.added, newR->functions->functions.size());
    // Changed/added/removed come before identical ones.
    bool seenIdentical = false;
    for (const auto& f : d.functions) {
        if (f.change == FunctionChange::Identical) {
            seenIdentical = true;
        } else {
            EXPECT_FALSE(seenIdentical);
        }
    }
}

TEST(Diff, FingerprintIgnoresAddresses) {
    const auto a = load("DASAWdmSample.sys");
    const auto b = load("DASATaintSample.sys");
    EXPECT_EQ(analysis::functionFingerprint(*a->functions->find(0x1400)),
              analysis::functionFingerprint(*b->functions->find(0x1480)));
    EXPECT_NE(analysis::functionFingerprint(*a->functions->find(0x1300)),
              analysis::functionFingerprint(*a->functions->find(0x1200)));
}

TEST(Assessment, TaintFixture) {
    const auto a = analysis::assess(*load("DASATaintSample.sys"));
    EXPECT_EQ(a.headline, "Request data from user mode reaches a dangerous operation.");
    EXPECT_EQ(a.score, 100);
    ASSERT_FALSE(a.topRisks.empty());
    EXPECT_EQ(a.topRisks.front().severity, "Critical");
    EXPECT_LE(a.topRisks.size(), 5u);
    EXPECT_TRUE(std::any_of(a.exposure.begin(), a.exposure.end(), [](const std::string& s) {
        return s.find(R"(\DosDevices\DasaTaint)") != std::string::npos;
    }));
    EXPECT_TRUE(contains(a.gaps, "A device is created without FILE_DEVICE_SECURE_OPEN."));
    // ProbeForRead is called, so it is listed as a protection.
    EXPECT_TRUE(contains(a.protections, "Validates user-mode buffers with ProbeForRead/ProbeForWrite."));
    EXPECT_FALSE(a.nextSteps.empty());
    EXPECT_FALSE(a.coverage.empty());
}

TEST(Assessment, WdmFixtureHasReachButNoFlow) {
    const auto a = analysis::assess(*load("DASAWdmSample.sys"));
    EXPECT_EQ(a.headline, "Dangerous capabilities are reachable from user requests.");
    EXPECT_FALSE(contains(a.protections, "Validates user-mode buffers with ProbeForRead/ProbeForWrite."));
    EXPECT_TRUE(std::any_of(a.exposure.begin(), a.exposure.end(), [](const std::string& s) {
        return s.find("IRP_MJ_DEVICE_CONTROL") != std::string::npos;
    }));
}
