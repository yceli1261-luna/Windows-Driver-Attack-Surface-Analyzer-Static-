#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <random>
#include <string>

#include "analysis/search/Search.h"
#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/database/AnalysisDatabase.h"

// Research tools (Phase 11): search over an analysis, and bookmarks / notes
// / tags in the database. Search expectations come from
// tests/fixtures/drivers/gen_wdm_fixture.py: the UTF-16 strings it places in
// .rdata (L"\Device\DasaWdm" at 0x2300, L"\DosDevices\DasaWdm" at 0x2340,
// L"ZwQuerySystemInformation" at 0x2380) and loads in DriverEntry (0x1000),
// MmMapIoSpace called in the helper at 0x1300, `wrmsr` at 0x132C, and the
// IOCTL 0x0022E00B compared there.

namespace fs = std::filesystem;
using namespace dasa;
using analysis::SearchKind;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

class TempDb {
public:
    TempDb() {
        std::random_device rd;
        path_ = fs::temp_directory_path() / ("dasa-research-" + std::to_string(rd()) + ".db");
    }
    ~TempDb() {
        std::error_code ec;
        fs::remove(path_, ec);
    }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

const analysis::SearchHit* hit(const analysis::SearchResults& r, SearchKind kind, const std::string& text) {
    for (const auto& h : r.hits) {
        if (h.kind == kind && h.text == text) {
            return &h;
        }
    }
    return nullptr;
}

std::shared_ptr<const analysis::AnalysisResult> wdm() {
    static const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    return r;
}

} // namespace

TEST(Search, StringsFromFixture) {
    const auto strings = analysis::extractStrings(*wdm()->image);
    auto at = [&](std::uint64_t rva) {
        return std::find_if(strings.begin(), strings.end(), [&](const auto& s) { return s.rva == rva; });
    };
    ASSERT_NE(at(0x2300), strings.end());
    EXPECT_EQ(at(0x2300)->text, R"(\Device\DasaWdm)");
    EXPECT_TRUE(at(0x2300)->utf16);
    EXPECT_EQ(at(0x2300)->section, ".rdata");
    ASSERT_NE(at(0x2340), strings.end());
    EXPECT_EQ(at(0x2340)->text, R"(\DosDevices\DasaWdm)");
    ASSERT_NE(at(0x2380), strings.end());
    EXPECT_EQ(at(0x2380)->text, "ZwQuerySystemInformation");
}

TEST(Search, KindsAndNavigation) {
    const auto r = analysis::search(*wdm(), "dasawdm");
    const auto* dev = hit(r, SearchKind::String, R"(\Device\DasaWdm)");
    ASSERT_NE(dev, nullptr);
    EXPECT_EQ(dev->rva, std::optional<std::uint64_t>(0x2300));
    EXPECT_EQ(dev->function, std::optional<std::uint64_t>(0x1000)); // loaded in DriverEntry
    EXPECT_NE(hit(r, SearchKind::Device, R"(\Device\DasaWdm)"), nullptr);
    EXPECT_NE(hit(r, SearchKind::Device, R"(\DosDevices\DasaWdm)"), nullptr);

    const auto imp = analysis::search(*wdm(), "MmMapIoSpace", {false, true, static_cast<std::uint32_t>(SearchKind::Import)});
    ASSERT_EQ(imp.hits.size(), 1u);
    EXPECT_EQ(imp.hits[0].context.rfind("ntoskrnl.exe", 0), 0u);
    EXPECT_EQ(imp.hits[0].function, std::optional<std::uint64_t>(0x1300));

    const auto ins = analysis::search(*wdm(), "wrmsr", {false, false, static_cast<std::uint32_t>(SearchKind::Instruction)});
    ASSERT_EQ(ins.hits.size(), 1u);
    EXPECT_EQ(ins.hits[0].rva, std::optional<std::uint64_t>(0x132C));
    EXPECT_EQ(ins.hits[0].function, std::optional<std::uint64_t>(0x1300));

    const auto io = analysis::search(*wdm(), "0x0022E00B", {false, false, static_cast<std::uint32_t>(SearchKind::Ioctl)});
    ASSERT_EQ(io.hits.size(), 1u);
    EXPECT_EQ(io.hits[0].function, std::optional<std::uint64_t>(0x1300));

    const auto fn = analysis::search(*wdm(), "0x1300", {false, false, static_cast<std::uint32_t>(SearchKind::Function)});
    ASSERT_EQ(fn.hits.size(), 1u);
    EXPECT_EQ(fn.hits[0].function, std::optional<std::uint64_t>(0x1300));
}

TEST(Search, OptionsAndErrors) {
    // Case sensitivity.
    EXPECT_TRUE(analysis::search(*wdm(), "dasawdm", {false, true, static_cast<std::uint32_t>(SearchKind::String)})
                    .hits.empty());
    EXPECT_FALSE(analysis::search(*wdm(), "DasaWdm", {false, true, static_cast<std::uint32_t>(SearchKind::String)})
                     .hits.empty());
    // Regex: instructions that compare edx with an immediate (cmp edx, 0x22e00b in the helper).
    const auto re = analysis::search(*wdm(), R"(^cmp edx, 0x)", {true, false, static_cast<std::uint32_t>(SearchKind::Instruction)});
    ASSERT_EQ(re.hits.size(), 1u);
    EXPECT_EQ(re.hits[0].rva, std::optional<std::uint64_t>(0x1300));
    const auto bad = analysis::search(*wdm(), "([", {true, false, analysis::kAllSearchKinds});
    EXPECT_FALSE(bad.error.empty());
    EXPECT_TRUE(bad.hits.empty());
    // Limit.
    const auto limited = analysis::search(*wdm(), "e", {false, false, analysis::kAllSearchKinds, 3});
    EXPECT_EQ(limited.hits.size(), 3u);
    EXPECT_TRUE(limited.truncated);
    EXPECT_TRUE(analysis::search(*wdm(), "").hits.empty());
}

TEST(Annotations, BookmarksNotesTags) {
    TempDb tmp;
    core::database::AnalysisDatabase db(tmp.path());
    const std::string a(64, 'a'), b(64, 'b');

    const auto id1 = db.addBookmark(a, 0x1320, "MmMapIoSpace call", "check the length");
    db.addBookmark(a, 0x1200, "dispatch", "");
    db.addBookmark(b, 0x1000, "other driver", "");
    auto marks = db.bookmarks(a);
    ASSERT_EQ(marks.size(), 2u);
    EXPECT_EQ(marks[0].rva, 0x1200u); // sorted by address
    EXPECT_EQ(marks[1].id, id1);
    EXPECT_EQ(marks[1].note, "check the length");
    EXPECT_EQ(marks[1].createdAt.size(), 19u);
    db.updateBookmark(id1, "map call", "length is constant");
    EXPECT_EQ(db.bookmarks(a)[1].label, "map call");
    db.removeBookmark(id1);
    EXPECT_EQ(db.bookmarks(a).size(), 1u);
    EXPECT_EQ(db.bookmarks(b).size(), 1u);

    EXPECT_EQ(db.notes(a), "");
    db.setNotes(a, "line 1\nline 2 \xE2\x9C\x93");
    EXPECT_EQ(db.notes(a), "line 1\nline 2 \xE2\x9C\x93"); // UTF-8 survives
    db.setNotes(a, "replaced");
    EXPECT_EQ(db.notes(a), "replaced");

    db.addTag(a, "  Vulnerable ");
    db.addTag(a, "vulnerable"); // same after normalising
    db.addTag(a, "reviewed");
    db.addTag(b, "reviewed");
    db.addTag(b, "   ");          // ignored
    EXPECT_EQ(db.tags(a), (std::vector<std::string>{"reviewed", "vulnerable"}));
    const auto all = db.allTags();
    ASSERT_EQ(all.size(), 2u);
    EXPECT_EQ(all[0].tag, "reviewed");
    EXPECT_EQ(all[0].drivers, 2);
    EXPECT_EQ(db.driversWithTag("VULNERABLE"), std::vector<std::string>{a});
    db.removeTag(a, "Vulnerable");
    EXPECT_EQ(db.tags(a), std::vector<std::string>{"reviewed"});

    const auto annotated = db.annotatedDrivers();
    ASSERT_EQ(annotated.size(), 2u);
    const auto da = std::find_if(annotated.begin(), annotated.end(), [&](const auto& d) { return d.sha256 == a; });
    ASSERT_NE(da, annotated.end());
    EXPECT_EQ(da->bookmarks, 1);
    EXPECT_TRUE(da->hasNotes);
    EXPECT_EQ(da->latest.id, 0); // never stored as an analysis

    db.setNotes(a, ""); // empty deletes
    EXPECT_EQ(db.notes(a), "");
}

TEST(Annotations, LatestAnalysisOfAnnotatedDriver) {
    TempDb tmp;
    core::database::AnalysisDatabase db(tmp.path());
    core::database::StoredAnalysis s;
    s.summary.fileName = "x.sys";
    s.summary.sha256 = std::string(64, 'c');
    s.summary.riskScore = 10;
    db.save(s, "{}");
    s.summary.riskScore = 42;
    const auto newest = db.save(s, "{}");
    db.addTag(s.summary.sha256, "triage");
    const auto annotated = db.annotatedDrivers();
    ASSERT_EQ(annotated.size(), 1u);
    EXPECT_EQ(annotated[0].latest.id, newest);
    EXPECT_EQ(annotated[0].latest.riskScore, 42);
    EXPECT_EQ(annotated[0].tags, std::vector<std::string>{"triage"});
}
