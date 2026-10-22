#include "core/database/AnalysisDatabase.h"

#include <algorithm>
#include <set>

#include <sqlite3.h>

namespace dasa::core::database {

namespace {

constexpr const char* kSchema = R"sql(
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS analyses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analyzed_at   TEXT NOT NULL DEFAULT (datetime('now')),
    file_path     TEXT NOT NULL,
    file_name     TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    file_size     INTEGER NOT NULL,
    model         TEXT NOT NULL,
    risk_score    INTEGER NOT NULL,
    risk_level    TEXT NOT NULL,
    function_count INTEGER NOT NULL,
    ioctl_count   INTEGER NOT NULL,
    device_count  INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    report_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS analyses_sha256 ON analyses(sha256);
CREATE INDEX IF NOT EXISTS analyses_name ON analyses(file_name);
CREATE TABLE IF NOT EXISTS findings (
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    category    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_analysis ON findings(analysis_id);
CREATE TABLE IF NOT EXISTS ioctls (
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    code        INTEGER NOT NULL,
    method      TEXT NOT NULL,
    access      TEXT NOT NULL,
    handler     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ioctls_analysis ON ioctls(analysis_id);
CREATE TABLE IF NOT EXISTS apis (
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    risk        TEXT NOT NULL,
    reachable   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS apis_analysis ON apis(analysis_id);
CREATE TABLE IF NOT EXISTS bookmarks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     TEXT NOT NULL,
    rva        INTEGER NOT NULL,
    label      TEXT NOT NULL,
    note       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS bookmarks_sha ON bookmarks(sha256);
CREATE TABLE IF NOT EXISTS notes (
    sha256     TEXT PRIMARY KEY,
    text       TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS tags (
    sha256     TEXT NOT NULL,
    tag        TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (sha256, tag)
);
)sql";

class Statement {
public:
    Statement(sqlite3* db, const char* sql) : m_db(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &m_stmt, nullptr) != SQLITE_OK) {
            throw DatabaseError(std::string("SQL prepare failed: ") + sqlite3_errmsg(db));
        }
    }
    ~Statement() { sqlite3_finalize(m_stmt); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    Statement& bind(int i, const std::string& v) {
        check(sqlite3_bind_text(m_stmt, i, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT));
        return *this;
    }
    Statement& bind(int i, std::int64_t v) {
        check(sqlite3_bind_int64(m_stmt, i, v));
        return *this;
    }
    /// true while a row is available.
    bool step() {
        const int rc = sqlite3_step(m_stmt);
        if (rc == SQLITE_ROW) {
            return true;
        }
        if (rc != SQLITE_DONE) {
            throw DatabaseError(std::string("SQL step failed: ") + sqlite3_errmsg(m_db));
        }
        return false;
    }
    void reset() {
        sqlite3_reset(m_stmt);
        sqlite3_clear_bindings(m_stmt);
    }
    std::string text(int col) const {
        const auto* p = sqlite3_column_text(m_stmt, col);
        return p ? reinterpret_cast<const char*>(p) : "";
    }
    std::int64_t integer(int col) const { return sqlite3_column_int64(m_stmt, col); }

private:
    void check(int rc) const {
        if (rc != SQLITE_OK) {
            throw DatabaseError(std::string("SQL bind failed: ") + sqlite3_errmsg(m_db));
        }
    }
    sqlite3* m_db;
    sqlite3_stmt* m_stmt = nullptr;
};

constexpr const char* kSummaryColumns =
    "id, analyzed_at, file_path, file_name, sha256, file_size, model, risk_score, risk_level, "
    "function_count, ioctl_count, device_count, finding_count";

AnalysisSummary readSummary(const Statement& s) {
    AnalysisSummary a;
    a.id = s.integer(0);
    a.analyzedAt = s.text(1);
    a.filePath = s.text(2);
    a.fileName = s.text(3);
    a.sha256 = s.text(4);
    a.fileSize = s.integer(5);
    a.model = s.text(6);
    a.riskScore = static_cast<int>(s.integer(7));
    a.riskLevel = s.text(8);
    a.functionCount = static_cast<int>(s.integer(9));
    a.ioctlCount = static_cast<int>(s.integer(10));
    a.deviceCount = static_cast<int>(s.integer(11));
    a.findingCount = static_cast<int>(s.integer(12));
    return a;
}

std::string findingKey(const StoredFinding& f) {
    return f.ruleId + "\x1f" + f.title;
}

} // namespace

struct AnalysisDatabase::Impl {
    sqlite3* db = nullptr;

    void exec(const char* sql) {
        char* err = nullptr;
        if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            std::string msg = err ? err : "unknown error";
            sqlite3_free(err);
            throw DatabaseError("SQL failed: " + msg);
        }
    }
};

AnalysisDatabase::AnalysisDatabase(const std::filesystem::path& path) : m_impl(std::make_unique<Impl>()) {
    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }
    const std::string utf8 = reinterpret_cast<const char*>(path.u8string().c_str());
    if (sqlite3_open(utf8.c_str(), &m_impl->db) != SQLITE_OK) {
        const std::string msg = m_impl->db ? sqlite3_errmsg(m_impl->db) : "out of memory";
        sqlite3_close(m_impl->db);
        m_impl->db = nullptr;
        throw DatabaseError("Cannot open database " + utf8 + ": " + msg);
    }
    sqlite3_busy_timeout(m_impl->db, 5000);
    m_impl->exec(kSchema);
}

AnalysisDatabase::~AnalysisDatabase() {
    if (m_impl && m_impl->db) {
        sqlite3_close(m_impl->db);
    }
}

std::int64_t AnalysisDatabase::save(const StoredAnalysis& a, const std::string& reportJson) {
    m_impl->exec("BEGIN");
    try {
        const auto& s = a.summary;
        Statement ins(m_impl->db,
                      "INSERT INTO analyses (file_path, file_name, sha256, file_size, model, risk_score, risk_level, "
                      "function_count, ioctl_count, device_count, finding_count, report_json) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
        ins.bind(1, s.filePath).bind(2, s.fileName).bind(3, s.sha256).bind(4, s.fileSize).bind(5, s.model);
        ins.bind(6, s.riskScore).bind(7, s.riskLevel).bind(8, s.functionCount).bind(9, s.ioctlCount);
        ins.bind(10, s.deviceCount).bind(11, s.findingCount).bind(12, reportJson);
        ins.step();
        const std::int64_t id = sqlite3_last_insert_rowid(m_impl->db);

        Statement f(m_impl->db, "INSERT INTO findings VALUES (?,?,?,?,?,?)");
        for (const auto& x : a.findings) {
            f.reset();
            f.bind(1, id).bind(2, x.ruleId).bind(3, x.title).bind(4, x.severity).bind(5, x.confidence).bind(6, x.category);
            f.step();
        }
        Statement io(m_impl->db, "INSERT INTO ioctls VALUES (?,?,?,?,?)");
        for (const auto& x : a.ioctls) {
            io.reset();
            io.bind(1, id).bind(2, static_cast<std::int64_t>(x.code)).bind(3, x.method).bind(4, x.access).bind(5, x.handler);
            io.step();
        }
        Statement ap(m_impl->db, "INSERT INTO apis VALUES (?,?,?,?)");
        for (const auto& x : a.apis) {
            ap.reset();
            ap.bind(1, id).bind(2, x.name).bind(3, x.risk).bind(4, x.reachable ? 1 : 0);
            ap.step();
        }
        m_impl->exec("COMMIT");
        return id;
    } catch (...) {
        m_impl->exec("ROLLBACK");
        throw;
    }
}

std::vector<AnalysisSummary> AnalysisDatabase::list(int limit) {
    Statement s(m_impl->db, (std::string("SELECT ") + kSummaryColumns +
                             " FROM analyses ORDER BY id DESC LIMIT ?").c_str());
    s.bind(1, static_cast<std::int64_t>(limit));
    std::vector<AnalysisSummary> out;
    while (s.step()) {
        out.push_back(readSummary(s));
    }
    return out;
}

std::vector<AnalysisSummary> AnalysisDatabase::history(const std::string& sha256, const std::string& fileName,
                                                       std::int64_t excludeId) {
    Statement s(m_impl->db, (std::string("SELECT ") + kSummaryColumns +
                             " FROM analyses WHERE (sha256 = ? OR lower(file_name) = lower(?)) AND id <> ? "
                             "ORDER BY id DESC").c_str());
    s.bind(1, sha256).bind(2, fileName).bind(3, excludeId);
    std::vector<AnalysisSummary> out;
    while (s.step()) {
        out.push_back(readSummary(s));
    }
    return out;
}

std::optional<StoredAnalysis> AnalysisDatabase::load(std::int64_t id) {
    StoredAnalysis a;
    {
        Statement s(m_impl->db, (std::string("SELECT ") + kSummaryColumns + " FROM analyses WHERE id = ?").c_str());
        s.bind(1, id);
        if (!s.step()) {
            return std::nullopt;
        }
        a.summary = readSummary(s);
    }
    {
        Statement s(m_impl->db, "SELECT rule_id, title, severity, confidence, category FROM findings WHERE analysis_id = ? ORDER BY rowid");
        s.bind(1, id);
        while (s.step()) {
            a.findings.push_back({s.text(0), s.text(1), s.text(2), s.text(3), s.text(4)});
        }
    }
    {
        Statement s(m_impl->db, "SELECT code, method, access, handler FROM ioctls WHERE analysis_id = ? ORDER BY code");
        s.bind(1, id);
        while (s.step()) {
            a.ioctls.push_back({static_cast<std::uint32_t>(s.integer(0)), s.text(1), s.text(2), s.text(3)});
        }
    }
    {
        Statement s(m_impl->db, "SELECT name, risk, reachable FROM apis WHERE analysis_id = ? ORDER BY name");
        s.bind(1, id);
        while (s.step()) {
            a.apis.push_back({s.text(0), s.text(1), s.integer(2) != 0});
        }
    }
    return a;
}

std::optional<std::string> AnalysisDatabase::reportJson(std::int64_t id) {
    Statement s(m_impl->db, "SELECT report_json FROM analyses WHERE id = ?");
    s.bind(1, id);
    if (!s.step()) {
        return std::nullopt;
    }
    return s.text(0);
}

void AnalysisDatabase::remove(std::int64_t id) {
    Statement s(m_impl->db, "DELETE FROM analyses WHERE id = ?");
    s.bind(1, id);
    s.step();
}

// ------------------------------------------------- research annotations ----

std::vector<Bookmark> AnalysisDatabase::bookmarks(const std::string& sha256) {
    Statement s(m_impl->db,
                "SELECT id, sha256, rva, label, note, created_at FROM bookmarks WHERE sha256 = ? ORDER BY rva, id");
    s.bind(1, sha256);
    std::vector<Bookmark> out;
    while (s.step()) {
        out.push_back({s.integer(0), s.text(1), static_cast<std::uint64_t>(s.integer(2)), s.text(3), s.text(4),
                       s.text(5)});
    }
    return out;
}

std::int64_t AnalysisDatabase::addBookmark(const std::string& sha256, std::uint64_t rva, const std::string& label,
                                           const std::string& note) {
    Statement s(m_impl->db, "INSERT INTO bookmarks (sha256, rva, label, note) VALUES (?,?,?,?)");
    s.bind(1, sha256).bind(2, static_cast<std::int64_t>(rva)).bind(3, label).bind(4, note);
    s.step();
    return sqlite3_last_insert_rowid(m_impl->db);
}

void AnalysisDatabase::updateBookmark(std::int64_t id, const std::string& label, const std::string& note) {
    Statement s(m_impl->db, "UPDATE bookmarks SET label = ?, note = ? WHERE id = ?");
    s.bind(1, label).bind(2, note).bind(3, id);
    s.step();
}

void AnalysisDatabase::removeBookmark(std::int64_t id) {
    Statement s(m_impl->db, "DELETE FROM bookmarks WHERE id = ?");
    s.bind(1, id);
    s.step();
}

std::string AnalysisDatabase::notes(const std::string& sha256) {
    Statement s(m_impl->db, "SELECT text FROM notes WHERE sha256 = ?");
    s.bind(1, sha256);
    return s.step() ? s.text(0) : std::string();
}

void AnalysisDatabase::setNotes(const std::string& sha256, const std::string& text) {
    if (text.empty()) {
        Statement s(m_impl->db, "DELETE FROM notes WHERE sha256 = ?");
        s.bind(1, sha256);
        s.step();
        return;
    }
    Statement s(m_impl->db,
                "INSERT INTO notes (sha256, text) VALUES (?, ?) "
                "ON CONFLICT(sha256) DO UPDATE SET text = excluded.text, updated_at = datetime('now')");
    s.bind(1, sha256).bind(2, text);
    s.step();
}

namespace {

std::string normalizeTag(const std::string& tag) {
    const auto first = tag.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = tag.find_last_not_of(" \t\r\n");
    std::string t = tag.substr(first, last - first + 1);
    for (char& c : t) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return t;
}

} // namespace

std::vector<std::string> AnalysisDatabase::tags(const std::string& sha256) {
    Statement s(m_impl->db, "SELECT tag FROM tags WHERE sha256 = ? ORDER BY tag");
    s.bind(1, sha256);
    std::vector<std::string> out;
    while (s.step()) {
        out.push_back(s.text(0));
    }
    return out;
}

void AnalysisDatabase::addTag(const std::string& sha256, const std::string& tag) {
    const std::string t = normalizeTag(tag);
    if (t.empty()) {
        return;
    }
    Statement s(m_impl->db, "INSERT OR IGNORE INTO tags (sha256, tag) VALUES (?, ?)");
    s.bind(1, sha256).bind(2, t);
    s.step();
}

void AnalysisDatabase::removeTag(const std::string& sha256, const std::string& tag) {
    Statement s(m_impl->db, "DELETE FROM tags WHERE sha256 = ? AND tag = ?");
    s.bind(1, sha256).bind(2, normalizeTag(tag));
    s.step();
}

std::vector<TagCount> AnalysisDatabase::allTags() {
    Statement s(m_impl->db, "SELECT tag, COUNT(*) FROM tags GROUP BY tag ORDER BY COUNT(*) DESC, tag");
    std::vector<TagCount> out;
    while (s.step()) {
        out.push_back({s.text(0), static_cast<int>(s.integer(1))});
    }
    return out;
}

std::vector<std::string> AnalysisDatabase::driversWithTag(const std::string& tag) {
    Statement s(m_impl->db, "SELECT sha256 FROM tags WHERE tag = ? ORDER BY created_at DESC");
    s.bind(1, normalizeTag(tag));
    std::vector<std::string> out;
    while (s.step()) {
        out.push_back(s.text(0));
    }
    return out;
}

std::vector<AnnotatedDriver> AnalysisDatabase::annotatedDrivers() {
    // Every file with an annotation and when it was last touched.
    Statement s(m_impl->db,
                "SELECT sha256, MAX(t) FROM ("
                "  SELECT sha256, created_at AS t FROM bookmarks"
                "  UNION ALL SELECT sha256, updated_at FROM notes"
                "  UNION ALL SELECT sha256, created_at FROM tags"
                ") GROUP BY sha256 ORDER BY MAX(t) DESC");
    std::vector<AnnotatedDriver> out;
    while (s.step()) {
        AnnotatedDriver d;
        d.sha256 = s.text(0);
        out.push_back(std::move(d));
    }
    for (auto& d : out) {
        {
            Statement q(m_impl->db, (std::string("SELECT ") + kSummaryColumns +
                                     " FROM analyses WHERE sha256 = ? ORDER BY id DESC LIMIT 1").c_str());
            q.bind(1, d.sha256);
            if (q.step()) {
                d.latest = readSummary(q);
            }
        }
        d.tags = tags(d.sha256);
        {
            Statement q(m_impl->db, "SELECT COUNT(*) FROM bookmarks WHERE sha256 = ?");
            q.bind(1, d.sha256);
            q.step();
            d.bookmarks = static_cast<int>(q.integer(0));
        }
        {
            Statement q(m_impl->db, "SELECT updated_at FROM notes WHERE sha256 = ?");
            q.bind(1, d.sha256);
            if (q.step()) {
                d.hasNotes = true;
                d.notesUpdatedAt = q.text(0);
            }
        }
    }
    return out;
}

Comparison compare(const StoredAnalysis& a, const StoredAnalysis& b) {
    Comparison c;
    c.a = a.summary;
    c.b = b.summary;
    c.riskDelta = b.summary.riskScore - a.summary.riskScore;

    std::set<std::string> keysA, keysB;
    for (const auto& f : a.findings) keysA.insert(findingKey(f));
    for (const auto& f : b.findings) keysB.insert(findingKey(f));
    for (const auto& f : a.findings) {
        (keysB.count(findingKey(f)) ? c.inBoth : c.onlyInA).push_back(f);
    }
    for (const auto& f : b.findings) {
        if (!keysA.count(findingKey(f))) c.onlyInB.push_back(f);
    }

    std::set<std::uint32_t> codesA, codesB;
    for (const auto& i : a.ioctls) codesA.insert(i.code);
    for (const auto& i : b.ioctls) codesB.insert(i.code);
    for (const auto& i : a.ioctls) if (!codesB.count(i.code)) c.ioctlsOnlyInA.push_back(i);
    for (const auto& i : b.ioctls) if (!codesA.count(i.code)) c.ioctlsOnlyInB.push_back(i);

    std::set<std::string> apisA, apisB;
    for (const auto& x : a.apis) apisA.insert(x.name);
    for (const auto& x : b.apis) apisB.insert(x.name);
    for (const auto& x : a.apis) if (!apisB.count(x.name)) c.apisOnlyInA.push_back(x);
    for (const auto& x : b.apis) if (!apisA.count(x.name)) c.apisOnlyInB.push_back(x);
    return c;
}

} // namespace dasa::core::database
