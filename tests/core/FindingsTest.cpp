#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <string>

#include "analysis/static/StaticAnalysisPipeline.h"

// Findings (Phase 7) over the full static pipeline. What each fixture
// contains comes from its generator (tests/fixtures/drivers/gen_*.py and
// v1's samples/_build_risky_sample.py); the rule ids, severities and score
// weights are DASA's own and are checked as such.

namespace fs = std::filesystem;
using namespace dasa;
using core::findings::EvidenceStep;
using core::findings::Finding;
using core::findings::FindingConfidence;
using core::findings::Severity;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

std::vector<const Finding*> byRule(const core::findings::FindingsReport& r, const std::string& id) {
    std::vector<const Finding*> out;
    for (const auto& f : r.findings) {
        if (f.ruleId == id) {
            out.push_back(&f);
        }
    }
    return out;
}

bool chainHas(const core::findings::EvidenceChain& c, EvidenceStep::Kind kind, const std::string& labelPart) {
    return std::any_of(c.begin(), c.end(), [&](const EvidenceStep& s) {
        return s.kind == kind && s.label.find(labelPart) != std::string::npos;
    });
}

} // namespace

TEST(RiskScore, Weights) {
    std::vector<Finding> fs(2);
    fs[0].ruleId = "A";
    fs[0].severity = Severity::Critical;
    fs[0].confidence = FindingConfidence::Medium; // 40 * 0.75 = 30
    fs[1].ruleId = "B";
    fs[1].severity = Severity::Low;
    fs[1].confidence = FindingConfidence::High; // 3
    const auto r = core::findings::scoreFindings(fs);
    EXPECT_EQ(r.score, 33);
    EXPECT_EQ(r.level, "Medium");
    ASSERT_EQ(r.contributions.size(), 2u);
    EXPECT_EQ(r.contributions[0].ruleId, "A");
    EXPECT_EQ(r.contributions[0].points, 30);
    EXPECT_EQ(core::findings::scoreFindings({}).level, "Minimal");
}

// DASAWdmSample.sys: \DosDevices\DasaWdm -> IRP_MJ_DEVICE_CONTROL (0x1200)
// -> helper 0x1300 (where IOCTL 0x0022E00B is compared) -> MmMapIoSpace /
// wrmsr / in. Device without FILE_DEVICE_SECURE_OPEN or SDDL, one
// METHOD_NEITHER IOCTL and no ProbeForRead/Write.
TEST(Findings, WdmFixture) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    const auto& report = *r->findings;

    const auto critical = byRule(report, "DASA-REACH-CRITICAL");
    // MmMapIoSpace (critical API) and wrmsr (critical instruction).
    ASSERT_EQ(critical.size(), 2u);
    const Finding* map = nullptr;
    for (const auto* f : critical) {
        if (f->title.find("MmMapIoSpace") != std::string::npos) {
            map = f;
        }
    }
    ASSERT_NE(map, nullptr);
    EXPECT_EQ(map->severity, Severity::Critical);
    ASSERT_EQ(map->evidence.size(), 1u);
    const auto& chain = map->evidence[0];
    EXPECT_TRUE(chainHas(chain, EvidenceStep::Kind::UserModeName, "\\DosDevices\\DasaWdm"));
    EXPECT_TRUE(chainHas(chain, EvidenceStep::Kind::EntryPoint, "IRP_MJ_DEVICE_CONTROL"));
    EXPECT_TRUE(chainHas(chain, EvidenceStep::Kind::Ioctl, "0x0022E00B"));
    EXPECT_TRUE(chainHas(chain, EvidenceStep::Kind::Function, "sub_1300"));
    EXPECT_TRUE(chainHas(chain, EvidenceStep::Kind::Call, "MmMapIoSpace"));
    EXPECT_EQ(chain.back().rva.value_or(0), 0x1320u); // the call instruction

    // Port read via `in` is a high-risk instruction.
    const auto high = byRule(report, "DASA-REACH-HIGH");
    ASSERT_EQ(high.size(), 1u);
    EXPECT_NE(high[0]->title.find("Port I/O read"), std::string::npos);

    EXPECT_EQ(byRule(report, "DASA-DEVICE-NO-SECURE-OPEN").size(), 1u);
    EXPECT_EQ(byRule(report, "DASA-DEVICE-DEFAULT-ACL").size(), 1u);

    const auto neither = byRule(report, "DASA-METHOD-NEITHER");
    ASSERT_EQ(neither.size(), 1u);
    EXPECT_EQ(neither[0]->severity, Severity::High); // no ProbeForRead/Write
    EXPECT_EQ(neither[0]->confidence, FindingConfidence::High);
    EXPECT_TRUE(chainHas(neither[0]->evidence.at(0), EvidenceStep::Kind::Ioctl, "0x0022E00B"));

    const auto any = byRule(report, "DASA-ANY-ACCESS");
    ASSERT_EQ(any.size(), 1u); // 0x00222000/04/08 are FILE_ANY_ACCESS
    EXPECT_NE(any[0]->title.find("3 IOCTLs"), std::string::npos);

    EXPECT_EQ(byRule(report, "DASA-RUNTIME-RESOLVED").size(), 1u); // ZwQuerySystemInformation
    EXPECT_EQ(byRule(report, "DASA-NO-EMBEDDED-SIGNATURE").size(), 1u);
    EXPECT_TRUE(byRule(report, "DASA-NO-NX").empty());   // fixture sets NX_COMPAT
    EXPECT_TRUE(byRule(report, "DASA-NO-ASLR").empty()); // and DYNAMIC_BASE

    // Most severe first, and two critical findings put the score at the top.
    EXPECT_EQ(report.findings.front().severity, Severity::Critical);
    EXPECT_EQ(report.risk.level, "Critical");
    EXPECT_GE(report.risk.score, 70);
}

// DASAKmdfSample.sys: no dangerous calls; one METHOD_NEITHER IOCTL
// (0x00222003) and no ProbeForRead/Write; the WDF device sets
// FILE_DEVICE_SECURE_OPEN.
TEST(Findings, KmdfFixture) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAKmdfSample.sys"));
    const auto& report = *r->findings;
    EXPECT_TRUE(byRule(report, "DASA-REACH-CRITICAL").empty());
    EXPECT_TRUE(byRule(report, "DASA-DEVICE-NO-SECURE-OPEN").empty());
    const auto neither = byRule(report, "DASA-METHOD-NEITHER");
    ASSERT_EQ(neither.size(), 1u);
    EXPECT_TRUE(chainHas(neither[0]->evidence.at(0), EvidenceStep::Kind::EntryPoint, "EvtIoDeviceControl"));
}

// DASARiskyDriver.sys imports critical APIs it never calls, has four
// METHOD_NEITHER codes (found as constants) and clears NX/ASLR.
TEST(Findings, RiskyFixture) {
    const auto r = analysis::runStaticAnalysis(fixture("DASARiskyDriver.sys"));
    const auto& report = *r->findings;
    EXPECT_TRUE(byRule(report, "DASA-REACH-CRITICAL").empty()); // nothing is actually called
    const auto uncalled = byRule(report, "DASA-UNCALLED-CRITICAL-IMPORT");
    EXPECT_GE(uncalled.size(), 4u);
    for (const auto* f : uncalled) {
        EXPECT_EQ(f->confidence, FindingConfidence::Low);
    }
    const auto neither = byRule(report, "DASA-METHOD-NEITHER");
    ASSERT_EQ(neither.size(), 1u);
    EXPECT_EQ(neither[0]->confidence, FindingConfidence::Medium); // constants, not tracked compares
    EXPECT_NE(neither[0]->title.find("4 METHOD_NEITHER"), std::string::npos);
    EXPECT_EQ(byRule(report, "DASA-NO-NX").size(), 1u);
    EXPECT_EQ(byRule(report, "DASA-NO-ASLR").size(), 1u);
}
