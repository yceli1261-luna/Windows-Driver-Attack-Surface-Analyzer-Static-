#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::analysis {

enum class SearchKind : std::uint32_t {
    Function = 1u << 0,
    Import = 1u << 1,
    Export = 1u << 2,
    String = 1u << 3,
    Instruction = 1u << 4,
    Ioctl = 1u << 5,
    Device = 1u << 6,
    Finding = 1u << 7,
};
constexpr std::uint32_t kAllSearchKinds = 0xFF;
const char* searchKindName(SearchKind k);

struct SearchHit {
    SearchKind kind = SearchKind::Function;
    std::string text;                    // what matched
    std::string context;                 // where: "sub_1300", "ntoskrnl.exe", ".rdata (UTF-16)", ...
    std::optional<std::uint64_t> rva;    // location to show
    std::optional<std::uint64_t> function; // function to open
};

struct SearchOptions {
    bool regex = false;         // ECMAScript regular expression instead of a substring
    bool caseSensitive = false;
    std::uint32_t kinds = kAllSearchKinds;
    std::size_t limit = 2000;
};

struct SearchResults {
    std::vector<SearchHit> hits;
    bool truncated = false; // stopped at the limit
    std::string error;      // invalid regular expression
};

/// Searches a finished analysis. Strings are ASCII and UTF-16LE runs of at
/// least 5 printable characters in non-executable sections; a string that
/// code references names the first referencing function.
SearchResults search(const AnalysisResult& result, const std::string& query, const SearchOptions& options = {});

struct FoundString {
    std::uint64_t rva = 0;
    std::string text;
    bool utf16 = false;
    std::string section;
};

std::vector<FoundString> extractStrings(const core::pe::PEImage& image, std::size_t minLength = 5);

} // namespace dasa::analysis
