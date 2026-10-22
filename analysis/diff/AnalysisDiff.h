#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::analysis {

/// How a function of the old version corresponds to the new one.
enum class FunctionChange {
    Identical, // same instruction fingerprint (addresses may differ)
    Changed,   // matched by name or by similar calls/size, but the code differs
    Added,     // only in the new version
    Removed,   // only in the old version
};
const char* functionChangeName(FunctionChange c);

struct FunctionDiff {
    FunctionChange change = FunctionChange::Identical;
    std::uint64_t oldRva = 0; // 0 when Added
    std::uint64_t newRva = 0; // 0 when Removed
    std::string oldName;
    std::string newName;
    std::size_t oldInstructions = 0;
    std::size_t newInstructions = 0;
    std::string matchedBy;  // "fingerprint", "name", "similar calls and size"
    std::vector<std::string> importsAdded, importsRemoved; // calls to imports (Changed only)
    bool touchesRiskyApi = false; // calls a high/critical API in either version
};

struct NamedDelta {
    std::vector<std::string> added, removed;
};

/// Differences between two analyses of (usually) two versions of a driver.
/// Functions are matched by an instruction fingerprint that ignores
/// addresses (branch targets, RIP-relative displacements, address
/// immediates), then by name (non-generic names), then by the set of
/// imports they call and their size. Useful for patch diffing: a security
/// fix usually shows up as a few Changed functions near the attack surface.
struct AnalysisDiff {
    std::string oldFile, newFile;
    bool sameFile = false; // identical SHA-256
    std::vector<FunctionDiff> functions; // Changed, Added, Removed, then Identical
    std::size_t identical = 0, changed = 0, added = 0, removed = 0;
    NamedDelta imports;  // "dll!name"
    NamedDelta exports;
    NamedDelta sections; // "name (characteristics)"
    NamedDelta ioctls;   // "0x00222000 METHOD_BUFFERED FILE_ANY_ACCESS"
    NamedDelta devices;  // device names and symbolic links
    NamedDelta findings; // "ruleId: title"
    int riskOld = 0, riskNew = 0;
};

AnalysisDiff diffAnalyses(const AnalysisResult& oldResult, const AnalysisResult& newResult);

/// The address-independent fingerprint used for matching (exposed for tests).
std::uint64_t functionFingerprint(const core::functions::Function& fn);

} // namespace dasa::analysis
