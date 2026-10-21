#pragma once

#include <QDateTime>
#include <QString>

#include "core/database/AnalysisDatabase.h"

namespace dasa::ui {

/// "YYYY-MM-DD HH:MM:SS" (UTC, as stored) shown in local time.
QString localTime(const std::string& utc);

/// One-line label for an analysis: "#12  beep.sys  2026-10-15 14:03  risk 3".
QString analysisLabel(const core::database::AnalysisSummary& s);

/// Rich-text rendering of a comparison, shared by Compare Drivers and
/// Previous Findings. `aName` / `bName` label the two sides.
QString comparisonHtml(const core::database::Comparison& c, const QString& aName, const QString& bName);

} // namespace dasa::ui
