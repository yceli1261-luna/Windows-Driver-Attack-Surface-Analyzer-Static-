#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace dasa::core::database {

class DatabaseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct AnalysisSummary {
    std::int64_t id = 0;
    std::string analyzedAt; // UTC, "YYYY-MM-DD HH:MM:SS"
    std::string filePath;
    std::string fileName;
    std::string sha256;
    std::int64_t fileSize = 0;
    std::string model;      // "WDM", "KMDF", ...
    int riskScore = 0;
    std::string riskLevel;
    int functionCount = 0;
    int ioctlCount = 0;
    int deviceCount = 0;
    int findingCount = 0;
};

struct StoredFinding {
    std::string ruleId;
    std::string title;
    std::string severity;   // "Critical", ...
    std::string confidence; // "high", ...
    std::string category;
};

struct StoredIoctl {
    std::uint32_t code = 0;
    std::string method;
    std::string access;
    std::string handler;
};

struct StoredApi {
    std::string name;
    std::string risk;  // "critical", ...
    bool reachable = false; // reached from some entry point
};

struct StoredAnalysis {
    AnalysisSummary summary;
    std::vector<StoredFinding> findings;
    std::vector<StoredIoctl> ioctls;
    std::vector<StoredApi> apis;
};

/// What changed between two stored analyses (A = older/baseline, B = newer).
struct Comparison {
    AnalysisSummary a, b;
    std::vector<StoredFinding> onlyInA, onlyInB, inBoth; // matched on rule id + title
    std::vector<StoredIoctl> ioctlsOnlyInA, ioctlsOnlyInB;
    std::vector<StoredApi> apisOnlyInA, apisOnlyInB;     // critical/high/medium only
    int riskDelta = 0;                                   // b - a
};

Comparison compare(const StoredAnalysis& a, const StoredAnalysis& b);

/// A saved location in a driver (keyed by the file's SHA-256, so it
/// survives re-analysis and renamed copies).
struct Bookmark {
    std::int64_t id = 0;
    std::string sha256;
    std::uint64_t rva = 0;
    std::string label;
    std::string note;
    std::string createdAt; // UTC "YYYY-MM-DD HH:MM:SS"
};

struct TagCount {
    std::string tag;
    int drivers = 0;
};

/// A driver with any bookmarks, notes or tags, with its latest analysis.
struct AnnotatedDriver {
    AnalysisSummary latest; // id 0 when the file was never stored as an analysis
    std::string sha256;
    std::vector<std::string> tags;
    int bookmarks = 0;
    bool hasNotes = false;
    std::string notesUpdatedAt;
};

/// SQLite store of past analyses: a summary row, the findings, IOCTLs and
/// notable APIs as rows for listing/comparison, and the full JSON report.
/// One connection per instance; use from one thread at a time.
class AnalysisDatabase {
public:
    /// Opens (creating if needed) the database file and its schema.
    explicit AnalysisDatabase(const std::filesystem::path& path);
    ~AnalysisDatabase();
    AnalysisDatabase(const AnalysisDatabase&) = delete;
    AnalysisDatabase& operator=(const AnalysisDatabase&) = delete;

    /// Inserts an analysis; the summary's id and analyzedAt are assigned.
    std::int64_t save(const StoredAnalysis& analysis, const std::string& reportJson);

    std::vector<AnalysisSummary> list(int limit = 500);
    /// Earlier analyses of the same file (same SHA-256 or same file name),
    /// newest first, excluding `excludeId`.
    std::vector<AnalysisSummary> history(const std::string& sha256, const std::string& fileName,
                                         std::int64_t excludeId);
    std::optional<StoredAnalysis> load(std::int64_t id);
    std::optional<std::string> reportJson(std::int64_t id);
    void remove(std::int64_t id);

    // ---- research annotations (per file SHA-256) -------------------------
    std::vector<Bookmark> bookmarks(const std::string& sha256);
    std::int64_t addBookmark(const std::string& sha256, std::uint64_t rva, const std::string& label,
                             const std::string& note);
    void updateBookmark(std::int64_t id, const std::string& label, const std::string& note);
    void removeBookmark(std::int64_t id);

    std::string notes(const std::string& sha256);
    /// Empty text deletes the notes.
    void setNotes(const std::string& sha256, const std::string& text);

    std::vector<std::string> tags(const std::string& sha256); // sorted
    /// Tags are trimmed and lower-cased; empty tags are ignored.
    void addTag(const std::string& sha256, const std::string& tag);
    void removeTag(const std::string& sha256, const std::string& tag);
    std::vector<TagCount> allTags(); // most used first
    std::vector<std::string> driversWithTag(const std::string& tag); // SHA-256s

    std::vector<AnnotatedDriver> annotatedDrivers(); // most recently annotated first

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace dasa::core::database
