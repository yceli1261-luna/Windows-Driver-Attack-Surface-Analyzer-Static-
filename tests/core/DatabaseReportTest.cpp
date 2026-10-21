#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <random>
#include <string>

#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include "analysis/report/ReportWriter.h"
#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/database/AnalysisDatabase.h"

// Analysis database and reports (Phase 8). The database tests store
// hand-written analyses and check they come back unchanged; the report
// tests check the WDM fixture's report against what its generator
// (tests/fixtures/drivers/gen_wdm_fixture.py) put in the file.

namespace fs = std::filesystem;
using namespace dasa;
using core::database::AnalysisDatabase;
using core::database::StoredAnalysis;
using nlohmann::json;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

// A database file in the temp directory, deleted afterwards.
class TempDb {
public:
    TempDb() {
        std::random_device rd;
        path_ = fs::temp_directory_path() / ("dasa-test-" + std::to_string(rd()) + ".db");
    }
    ~TempDb() {
        std::error_code ec;
        fs::remove(path_, ec);
    }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

StoredAnalysis sample(const std::string& name, const std::string& sha, int score) {
    StoredAnalysis a;
    a.summary.filePath = "C:\\drivers\\" + name;
    a.summary.fileName = name;
    a.summary.sha256 = sha;
    a.summary.fileSize = 4096;
    a.summary.model = "WDM";
    a.summary.riskScore = score;
    a.summary.riskLevel = score >= 70 ? "Critical" : "Low";
    a.summary.functionCount = 5;
    a.summary.ioctlCount = 2;
    a.summary.deviceCount = 1;
    a.summary.findingCount = 2;
    a.findings = {{"DASA-REACH-CRITICAL", "MmMapIoSpace reachable", "Critical", "high", "Reachability"},
                  {"DASA-NO-NX", "No NX", "Low", "high", "Hardening"}};
    a.ioctls = {{0x222000, "METHOD_BUFFERED", "FILE_ANY_ACCESS", "IRP_MJ_DEVICE_CONTROL"},
                {0x22E00B, "METHOD_NEITHER", "FILE_READ_DATA | FILE_WRITE_DATA", "IRP_MJ_DEVICE_CONTROL"}};
    a.apis = {{"MmMapIoSpace", "critical", true}, {"ZwOpenKey", "medium", false}};
    return a;
}

} // namespace

TEST(AnalysisDatabase, SaveLoadRoundTrip) {
    TempDb tmp;
    AnalysisDatabase db(tmp.path());
    const auto in = sample("Beep.sys", std::string(64, 'a'), 72);
    const auto id = db.save(in, R"({"schema":"dasa-report/1"})");
    ASSERT_GT(id, 0);

    const auto out = db.load(id);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->summary.id, id);
    EXPECT_EQ(out->summary.analyzedAt.size(), 19u); // "YYYY-MM-DD HH:MM:SS"
    EXPECT_EQ(out->summary.filePath, in.summary.filePath);
    EXPECT_EQ(out->summary.fileName, "Beep.sys");
    EXPECT_EQ(out->summary.sha256, in.summary.sha256);
    EXPECT_EQ(out->summary.fileSize, 4096);
    EXPECT_EQ(out->summary.riskScore, 72);
    EXPECT_EQ(out->summary.riskLevel, "Critical");
    EXPECT_EQ(out->summary.findingCount, 2);

    ASSERT_EQ(out->findings.size(), 2u);
    EXPECT_EQ(out->findings[0].ruleId, "DASA-REACH-CRITICAL"); // insertion order kept
    EXPECT_EQ(out->findings[1].title, "No NX");
    ASSERT_EQ(out->ioctls.size(), 2u);
    EXPECT_EQ(out->ioctls[1].code, 0x22E00Bu);
    EXPECT_EQ(out->ioctls[1].method, "METHOD_NEITHER");
    ASSERT_EQ(out->apis.size(), 2u);
    EXPECT_EQ(out->apis[0].name, "MmMapIoSpace");
    EXPECT_TRUE(out->apis[0].reachable);
    EXPECT_FALSE(out->apis[1].reachable);

    EXPECT_EQ(db.reportJson(id), std::optional<std::string>(R"({"schema":"dasa-report/1"})"));
    EXPECT_FALSE(db.load(id + 100).has_value());
}

TEST(AnalysisDatabase, PersistsAcrossConnections) {
    TempDb tmp;
    std::int64_t id = 0;
    {
        AnalysisDatabase db(tmp.path());
        id = db.save(sample("a.sys", "1", 10), "{}");
    }
    AnalysisDatabase reopened(tmp.path());
    const auto rows = reopened.list();
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].id, id);
}

TEST(AnalysisDatabase, ListHistoryAndRemove) {
    TempDb tmp;
    AnalysisDatabase db(tmp.path());
    const auto first = db.save(sample("Beep.sys", "sha-old", 10), "{}");
    const auto other = db.save(sample("null.sys", "sha-null", 0), "{}");
    const auto renamed = db.save(sample("beep_copy.sys", "sha-old", 10), "{}"); // same bytes, other name
    const auto newer = db.save(sample("BEEP.SYS", "sha-new", 20), "{}");      // same name, other bytes

    const auto all = db.list();
    ASSERT_EQ(all.size(), 4u);
    EXPECT_EQ(all[0].id, newer); // newest first
    EXPECT_EQ(all[3].id, first);
    EXPECT_EQ(db.list(2).size(), 2u);

    // Earlier analyses of BEEP.SYS: same name (case-insensitive) or same SHA-256.
    const auto h = db.history("sha-new", "BEEP.SYS", newer);
    ASSERT_EQ(h.size(), 1u);
    EXPECT_EQ(h[0].id, first);
    const auto h2 = db.history("sha-old", "beep_copy.sys", renamed);
    ASSERT_EQ(h2.size(), 1u);
    EXPECT_EQ(h2[0].id, first);

    db.remove(first);
    EXPECT_FALSE(db.load(first).has_value());
    EXPECT_EQ(db.list().size(), 3u);
    EXPECT_TRUE(db.history("sha-new", "BEEP.SYS", newer).empty());
    EXPECT_TRUE(db.load(other).has_value());
}

TEST(AnalysisDatabase, RemoveDeletesChildRows) {
    TempDb tmp;
    std::int64_t keep = 0;
    {
        AnalysisDatabase db(tmp.path());
        const auto gone = db.save(sample("a.sys", "1", 10), "{}");
        keep = db.save(sample("b.sys", "2", 10), "{}");
        db.remove(gone);
    }
    // Count the child rows with SQLite directly: only b.sys's 2 + 2 + 2 remain.
    sqlite3* raw = nullptr;
    ASSERT_EQ(sqlite3_open(tmp.path().string().c_str(), &raw), SQLITE_OK);
    for (const char* table : {"findings", "ioctls", "apis"}) {
        sqlite3_stmt* st = nullptr;
        const std::string sql = std::string("SELECT COUNT(*), MIN(analysis_id) FROM ") + table;
        ASSERT_EQ(sqlite3_prepare_v2(raw, sql.c_str(), -1, &st, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
        EXPECT_EQ(sqlite3_column_int(st, 0), 2) << table;
        EXPECT_EQ(sqlite3_column_int64(st, 1), keep) << table;
        sqlite3_finalize(st);
    }
    sqlite3_close(raw);
}

TEST(AnalysisDatabase, Compare) {
    auto older = sample("x.sys", "1", 20);
    auto newer = sample("x.sys", "2", 48);
    newer.findings.erase(newer.findings.begin() + 1);                           // No NX fixed
    newer.findings.push_back({"DASA-METHOD-NEITHER", "METHOD_NEITHER", "High", "medium", "IOCTL"});
    newer.ioctls.push_back({0x222010, "METHOD_BUFFERED", "FILE_ANY_ACCESS", "IRP_MJ_DEVICE_CONTROL"});
    newer.apis.erase(newer.apis.begin() + 1);                                   // ZwOpenKey gone

    const auto c = core::database::compare(older, newer);
    EXPECT_EQ(c.riskDelta, 28);
    ASSERT_EQ(c.onlyInA.size(), 1u);
    EXPECT_EQ(c.onlyInA[0].ruleId, "DASA-NO-NX");
    ASSERT_EQ(c.onlyInB.size(), 1u);
    EXPECT_EQ(c.onlyInB[0].ruleId, "DASA-METHOD-NEITHER");
    ASSERT_EQ(c.inBoth.size(), 1u);
    EXPECT_EQ(c.inBoth[0].ruleId, "DASA-REACH-CRITICAL");
    EXPECT_TRUE(c.ioctlsOnlyInA.empty());
    ASSERT_EQ(c.ioctlsOnlyInB.size(), 1u);
    EXPECT_EQ(c.ioctlsOnlyInB[0].code, 0x222010u);
    ASSERT_EQ(c.apisOnlyInA.size(), 1u);
    EXPECT_EQ(c.apisOnlyInA[0].name, "ZwOpenKey");
    EXPECT_TRUE(c.apisOnlyInB.empty());

    // Same rule, different title: two different findings.
    auto retitled = older;
    retitled.findings[0].title = "ZwMapViewOfSection reachable";
    const auto c2 = core::database::compare(older, retitled);
    EXPECT_EQ(c2.onlyInA.size(), 1u);
    EXPECT_EQ(c2.onlyInB.size(), 1u);
}

TEST(Report, HtmlEscape) {
    EXPECT_EQ(analysis::htmlEscape(R"(<a href="x">Tom & 'Jerry'</a>)"),
              "&lt;a href=&quot;x&quot;&gt;Tom &amp; &#39;Jerry&#39;&lt;/a&gt;");
    EXPECT_EQ(analysis::htmlEscape("\\Device\\DasaWdm"), "\\Device\\DasaWdm");
}

// The WDM fixture: IoCreateDevice("\Device\DasaWdm"), link
// "\DosDevices\DasaWdm", IRP_MJ_DEVICE_CONTROL comparing 0x00222000/04/08
// and (in a helper) 0x0022E00B, MmMapIoSpace reachable from it.
TEST(Report, JsonForWdmFixture) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    const auto j = json::parse(analysis::reportJson(*r));

    EXPECT_EQ(j["schema"], "dasa-report/1");
    EXPECT_EQ(j["file"]["name"], "DASAWdmSample.sys");
    EXPECT_EQ(j["file"]["sha256"].get<std::string>().size(), 64u);
    EXPECT_EQ(j["pe"]["entryPointRva"], "0x00001000");
    EXPECT_EQ(j["pe"]["pe32plus"], true);
    EXPECT_EQ(j["driver"]["model"], "WDM");

    std::vector<std::string> codes;
    for (const auto& x : j["ioctls"]) {
        codes.push_back(x["code"]);
    }
    for (const char* code : {"0x00222000", "0x00222004", "0x00222008", "0x0022E00B"}) {
        EXPECT_NE(std::find(codes.begin(), codes.end(), code), codes.end()) << code;
    }
    EXPECT_EQ(std::find(codes.begin(), codes.end(), "0x00010000"), codes.end()); // the length decoy

    const auto& devs = j["devices"]["deviceObjects"];
    ASSERT_FALSE(devs.empty());
    EXPECT_EQ(devs[0]["name"], "\\Device\\DasaWdm");
    EXPECT_EQ(devs[0]["secureOpen"], false);
    ASSERT_FALSE(j["devices"]["symbolicLinks"].empty());
    EXPECT_EQ(j["devices"]["symbolicLinks"][0]["link"], "\\DosDevices\\DasaWdm");

    const auto api = std::find_if(j["kernelApis"].begin(), j["kernelApis"].end(),
                                  [](const json& a) { return a["name"] == "MmMapIoSpace"; });
    ASSERT_NE(api, j["kernelApis"].end());
    EXPECT_EQ((*api)["reachableFrom"], json::array({"IRP_MJ_DEVICE_CONTROL"}));

    // The report carries the pipeline's findings and score unchanged.
    ASSERT_EQ(j["findings"].size(), r->findings->findings.size());
    EXPECT_EQ(j["risk"]["score"], r->findings->risk.score);
    const bool hasCritical = std::any_of(j["findings"].begin(), j["findings"].end(),
                                         [](const json& f) { return f["ruleId"] == "DASA-REACH-CRITICAL"; });
    EXPECT_TRUE(hasCritical);
    EXPECT_FALSE(j["findings"][0]["evidence"].empty());
}

TEST(Report, HtmlForWdmFixture) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    const auto html = analysis::reportHtml(*r);
    EXPECT_EQ(html.rfind("<!doctype html>", 0), 0u);
    EXPECT_NE(html.find("\\Device\\DasaWdm"), std::string::npos);
    EXPECT_NE(html.find("0x0022E00B"), std::string::npos);
    EXPECT_NE(html.find("MmMapIoSpace"), std::string::npos);
    EXPECT_EQ(html.find("<script"), std::string::npos);
    EXPECT_NE(html.find("</html>"), std::string::npos);
}

TEST(Report, SaveAnalysisOfWdmFixture) {
    TempDb tmp;
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    AnalysisDatabase db(tmp.path());
    const auto id = analysis::saveAnalysis(db, *r);
    const auto a = db.load(id);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->summary.fileName, "DASAWdmSample.sys");
    EXPECT_EQ(a->summary.model, "WDM");
    EXPECT_EQ(a->summary.ioctlCount, static_cast<int>(a->ioctls.size()));
    EXPECT_EQ(a->summary.findingCount, static_cast<int>(a->findings.size()));

    const auto code = std::find_if(a->ioctls.begin(), a->ioctls.end(), [](const auto& x) { return x.code == 0x22E00B; });
    ASSERT_NE(code, a->ioctls.end());
    EXPECT_EQ(code->method, "METHOD_NEITHER"); // CTL_CODE method bits of 0x0022E00B are 3

    const auto map = std::find_if(a->apis.begin(), a->apis.end(), [](const auto& x) { return x.name == "MmMapIoSpace"; });
    ASSERT_NE(map, a->apis.end());
    EXPECT_TRUE(map->reachable);

    // The stored report is the JSON report.
    const auto stored = db.reportJson(id);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(json::parse(*stored)["file"]["name"], "DASAWdmSample.sys");

    // Analyzing it again: Previous Findings sees the first run, nothing changed.
    const auto id2 = analysis::saveAnalysis(db, *r);
    const auto h = db.history(a->summary.sha256, a->summary.fileName, id2);
    ASSERT_EQ(h.size(), 1u);
    EXPECT_EQ(h[0].id, id);
    const auto c = core::database::compare(*db.load(id), *db.load(id2));
    EXPECT_TRUE(c.onlyInA.empty());
    EXPECT_TRUE(c.onlyInB.empty());
    EXPECT_EQ(c.riskDelta, 0);
}
