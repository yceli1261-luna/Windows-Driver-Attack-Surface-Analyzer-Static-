#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "analysis/static/StaticAnalysisPipeline.h"

namespace dasa::analysis {

/// A plain-language security assessment of one analysed driver, built from
/// the findings and the analysis stages: what the verdict is, how user mode
/// reaches the driver, the most important risks, which protections are in
/// place and which are missing, what to check next, and what the analysis
/// could not cover. Every statement is derived from recovered evidence.
struct Assessment {
    std::string headline; // one sentence
    std::string verdict;  // a short paragraph
    int score = 0;
    std::string level;

    std::vector<std::string> exposure;

    struct Risk {
        std::string severity;
        std::string confidence;
        std::string title;
        std::string ruleId;
        std::string why;
        std::optional<std::uint64_t> function;
    };
    std::vector<Risk> topRisks; // up to 5, most severe first

    std::vector<std::string> protections; // in place
    std::vector<std::string> gaps;        // missing
    std::vector<std::string> nextSteps;
    std::vector<std::string> coverage;    // limits that applied
};

Assessment assess(const AnalysisResult& result);

} // namespace dasa::analysis
