#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <string>

#include "analysis/report/PlainLanguage.h"
#include "analysis/static/StaticAnalysisPipeline.h"

// Simple mode wording (Phase 13). The fixtures' contents are known from their
// generators: DASATaintSample.sys passes request data into a memory write
// and MmMapIoSpace and has a public, unrestricted device; DASAWdmSample.sys
// reaches MmMapIoSpace and wrmsr from its IOCTL handler with constants.

namespace fs = std::filesystem;
using namespace dasa;
using analysis::Verdict;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

} // namespace

TEST(PlainLanguage, TaintFixture) {
    const auto r = analysis::runStaticAnalysis(fixture("DASATaintSample.sys"));
    const auto s = analysis::explain(*r);
    EXPECT_EQ(s.verdict, Verdict::Dangerous);
    EXPECT_STREQ(analysis::verdictName(s.verdict), "Dangerous");
    ASSERT_FALSE(s.canDo.empty());
    EXPECT_EQ(s.canDo.front(), "Write to any part of memory when a program asks it to.");
    EXPECT_TRUE(contains(s.canDo, "Read or change your computer's physical memory - where everything, including "
                                  "Windows itself, lives."));
    EXPECT_EQ(s.whoCanUse.rfind("Probably any program on this PC", 0), 0u);
    EXPECT_FALSE(s.whatToDo.empty());

    // One plain problem per finding, in the same (most serious first) order,
    // except reachability findings that a data-flow finding already covers:
    // MmMapIoSpace and wrmsr each have both, so 2 are left out.
    ASSERT_EQ(s.problems.size() + 2, r->findings->findings.size());
    for (std::size_t i = 0; i < s.problems.size(); ++i) {
        if (i > 0) {
            EXPECT_GT(s.problems[i].findingIndex, s.problems[i - 1].findingIndex);
        }
        EXPECT_FALSE(s.problems[i].headline.empty());
        EXPECT_EQ(s.problems[i].explanation.find("Data flow:"), std::string::npos) << s.problems[i].explanation;
    }
    const auto write = std::find_if(s.problems.begin(), s.problems.end(), [&](const auto& p) {
        return r->findings->findings[p.findingIndex].ruleId == "DASA-TAINT-WRITE";
    });
    ASSERT_NE(write, s.problems.end());
    EXPECT_EQ(write->headline, "Programs can make this driver write to any place in memory.");
    EXPECT_EQ(write->seriousness, "Serious");
    // No reverse-engineering jargon in the headlines.
    for (const auto& p : s.problems) {
        for (const char* jargon : {"IOCTL", "IRP", "RVA", "METHOD_NEITHER", "0x"}) {
            EXPECT_EQ(p.headline.find(jargon), std::string::npos) << p.headline;
        }
    }
}

TEST(PlainLanguage, WdmFixtureCapabilities) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    const auto s = analysis::explain(*r);
    EXPECT_EQ(s.verdict, Verdict::Dangerous); // risk 100: critical capabilities reachable
    EXPECT_TRUE(contains(s.canDo, "Talk directly to hardware or change low-level processor settings."));
    EXPECT_FALSE(contains(s.canDo, "Write to any part of memory when a program asks it to.")); // no such flow
}

TEST(PlainLanguage, QuietDriverIsSafe) {
    const fs::path null = R"(C:\Windows\System32\drivers\null.sys)";
    if (!fs::exists(null)) {
        GTEST_SKIP() << "null.sys not present";
    }
    const auto s = analysis::explain(*analysis::runStaticAnalysis(null));
    EXPECT_EQ(s.verdict, Verdict::Safe);
    EXPECT_EQ(s.canDo, std::vector<std::string>{"Nothing dangerous that programs can trigger was found."});
}

TEST(PlainLanguage, Glossary) {
    const auto& g = analysis::glossary();
    EXPECT_GE(g.size(), 10u);
    EXPECT_TRUE(std::any_of(g.begin(), g.end(), [](const auto& e) { return e.term == "IOCTL"; }));
}
