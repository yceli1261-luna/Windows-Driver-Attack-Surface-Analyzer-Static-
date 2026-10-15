#include "core/findings/Finding.h"

#include <algorithm>
#include <cmath>

namespace dasa::core::findings {

const char* severityName(Severity s) {
    switch (s) {
    case Severity::Critical: return "Critical";
    case Severity::High: return "High";
    case Severity::Medium: return "Medium";
    case Severity::Low: return "Low";
    case Severity::Info: break;
    }
    return "Info";
}

const char* confidenceName(FindingConfidence c) {
    switch (c) {
    case FindingConfidence::High: return "high";
    case FindingConfidence::Medium: return "medium";
    case FindingConfidence::Low: break;
    }
    return "low";
}

int FindingsReport::count(Severity s) const {
    return static_cast<int>(std::count_if(findings.begin(), findings.end(),
                                          [s](const Finding& f) { return f.severity == s; }));
}

RiskScore scoreFindings(const std::vector<Finding>& findings) {
    RiskScore r;
    double total = 0;
    for (const auto& f : findings) {
        int base = 0;
        switch (f.severity) {
        case Severity::Critical: base = 40; break;
        case Severity::High: base = 20; break;
        case Severity::Medium: base = 8; break;
        case Severity::Low: base = 3; break;
        case Severity::Info: base = 0; break;
        }
        const double factor = f.confidence == FindingConfidence::High     ? 1.0
                              : f.confidence == FindingConfidence::Medium ? 0.75
                                                                          : 0.5;
        const int points = static_cast<int>(std::lround(base * factor));
        if (points > 0) {
            r.contributions.push_back({f.ruleId, f.title, points});
            total += points;
        }
    }
    std::sort(r.contributions.begin(), r.contributions.end(),
              [](const auto& a, const auto& b) { return a.points > b.points; });
    r.score = static_cast<int>(std::min(100.0, total));
    r.level = r.score >= 70 ? "Critical" : r.score >= 40 ? "High" : r.score >= 15 ? "Medium" : r.score > 0 ? "Low" : "Minimal";
    return r;
}

} // namespace dasa::core::findings
