#pragma once

#include <string>
#include <vector>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::analysis {

/// The beginner view of an analysis: the same evidence as the findings, said
/// without reverse-engineering vocabulary. All wording comes from fixed
/// templates per finding rule and capability category, so it never claims
/// more than the analysis found.

enum class Verdict { Safe, WorthALook, Risky, Dangerous };
const char* verdictName(Verdict v); // "Safe", "Worth a look", "Risky", "Dangerous"

struct PlainProblem {
    std::string seriousness;  // "Serious", "High", "Moderate", "Minor", "Note"
    std::string headline;     // one plain sentence
    std::string explanation;  // what DASA saw, in plain words
    std::string consequence;  // what could happen
    std::size_t findingIndex = 0; // into FindingsReport::findings (for the technical details)
};

struct PlainSummary {
    Verdict verdict = Verdict::Safe;
    std::string verdictLine;               // one sentence under the traffic light
    std::vector<std::string> canDo;        // "What can this driver do?"
    std::string whoCanUse;                 // "Who can use it?"
    std::vector<std::string> whatToDo;     // "What should I do?"
    std::vector<PlainProblem> problems;    // most serious first; a reachability finding
                                           // repeated by a data-flow finding is left out
};

PlainSummary explain(const AnalysisResult& result);

/// One-sentence explanations of technical terms, for the glossary.
struct GlossaryEntry {
    std::string term;
    std::string meaning;
};
const std::vector<GlossaryEntry>& glossary();

} // namespace dasa::analysis
