#pragma once

#include <cstdint>
#include <string>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/database/AnalysisDatabase.h"

namespace dasa::analysis {

/// Everything the pipeline found, as JSON (schema "dasa-report/1"). Numbers
/// that are addresses or codes are hex strings ("0x00001200"). The same
/// document is stored in the analysis database.
std::string reportJson(const AnalysisResult& result, int indent = 2);

/// A self-contained HTML report (inline CSS, no scripts or external
/// resources): summary, findings with evidence, IOCTLs, devices, risky
/// kernel APIs, driver model and PE details. All driver-derived text is
/// HTML-escaped.
std::string reportHtml(const AnalysisResult& result);

/// Stores the result in `db` and returns the new analysis id.
std::int64_t saveAnalysis(core::database::AnalysisDatabase& db, const AnalysisResult& result);

/// HTML-escapes text (exposed for tests).
std::string htmlEscape(const std::string& text);

} // namespace dasa::analysis
