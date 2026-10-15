#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dasa::core::findings {

enum class Severity { Info, Low, Medium, High, Critical };
enum class FindingConfidence { Low, Medium, High };

const char* severityName(Severity s);
const char* confidenceName(FindingConfidence c);

/// One link in an evidence chain, e.g. a device name, an IRP handler, an
/// IOCTL code, a function, a call site.
struct EvidenceStep {
    enum class Kind { UserModeName, Device, EntryPoint, Ioctl, Function, Call, Instruction, Header, Note };
    Kind kind = Kind::Note;
    std::string label;                 // "\\DosDevices\\Foo", "IRP_MJ_DEVICE_CONTROL", "MmMapIoSpace", ...
    std::string detail;                // supporting text
    std::optional<std::uint64_t> rva;  // where to look (function start or instruction)
    std::optional<std::uint64_t> function; // function to open for this step
};

using EvidenceChain = std::vector<EvidenceStep>;

/// A finding is a claim plus the evidence for it - never a bare rule hit.
struct Finding {
    std::string ruleId;   // stable id, e.g. "DASA-REACH-CRITICAL-API"
    std::string title;
    std::string category; // "Exposed capability", "Device security", "Input handling", "Hardening", ...
    Severity severity = Severity::Info;
    FindingConfidence confidence = FindingConfidence::Medium;
    std::string description;
    std::string recommendation;
    std::vector<EvidenceChain> evidence;
};

/// Weighted sum of findings on a 0-100 scale. A heuristic for triage and
/// for comparing drivers, not a measure of exploitability.
struct RiskScore {
    int score = 0;
    std::string level; // Minimal / Low / Medium / High / Critical
    struct Contribution {
        std::string ruleId;
        std::string title;
        int points = 0;
    };
    std::vector<Contribution> contributions;
};

struct FindingsReport {
    std::vector<Finding> findings; // most severe first
    RiskScore risk;
    std::vector<std::string> notes;

    int count(Severity s) const;
};

/// Scores findings: Critical 40, High 20, Medium 8, Low 3, Info 0 points,
/// scaled by confidence (high 1.0, medium 0.75, low 0.5), summed and capped
/// at 100. Levels: >= 70 Critical, >= 40 High, >= 15 Medium, > 0 Low,
/// otherwise Minimal.
RiskScore scoreFindings(const std::vector<Finding>& findings);

} // namespace dasa::core::findings
