#include "analysis/report/Assessment.h"

#include <algorithm>
#include <set>

#include "core/ioctl/IoctlCodec.h"

namespace dasa::analysis {

namespace fnd = core::findings;

namespace {

bool hasRule(const fnd::FindingsReport& r, const std::string& prefix) {
    return std::any_of(r.findings.begin(), r.findings.end(),
                       [&](const fnd::Finding& f) { return f.ruleId.rfind(prefix, 0) == 0; });
}

const fnd::Finding* firstRule(const fnd::FindingsReport& r, const std::string& prefix) {
    for (const auto& f : r.findings) {
        if (f.ruleId.rfind(prefix, 0) == 0) {
            return &f;
        }
    }
    return nullptr;
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (const auto& s : v) {
        out += (out.empty() ? "" : sep) + s;
    }
    return out;
}

} // namespace

Assessment assess(const AnalysisResult& r) {
    Assessment a;
    const auto& findings = *r.findings;
    const auto& dev = *r.devices;
    const auto& drv = *r.driver;
    a.score = findings.risk.score;
    a.level = findings.risk.level;

    // ---- exposure: how user mode gets to the driver
    std::vector<std::string> names;
    for (const auto& l : dev.symbolicLinks) {
        if (!l.link.empty()) names.push_back(l.link);
    }
    for (const auto& d : dev.devices) {
        if (!d.name.empty()) {
            a.exposure.push_back("Creates device " + d.name + " (" + d.api + ")" +
                                 (d.sddl.empty() ? "" : " with SDDL " + d.sddl));
        }
    }
    if (!names.empty()) {
        a.exposure.push_back("User-mode programs can open it as " + join(names, ", ") + ".");
    }
    for (const auto& i : dev.interfaces) {
        a.exposure.push_back("Registers device interface " + (i.guid.empty() ? std::string("(GUID not resolved)") : i.guid) +
                             " - discoverable by user-mode programs.");
    }
    if (dev.devices.empty() && names.empty() && dev.interfaces.empty()) {
        a.exposure.push_back("No device name, symbolic link or interface was recovered; the driver may still be "
                             "reachable through its PnP stack or a name built at runtime.");
    }
    std::vector<std::string> handlers;
    for (const auto& m : drv.majorFunctions) {
        handlers.push_back(core::driver::irpMajorName(m.major));
    }
    for (const auto& q : drv.wdfQueues) {
        for (const auto& cb : q.callbacks) {
            handlers.push_back(cb.name);
        }
    }
    if (!handlers.empty()) {
        std::sort(handlers.begin(), handlers.end());
        handlers.erase(std::unique(handlers.begin(), handlers.end()), handlers.end());
        a.exposure.push_back("Handles " + join(handlers, ", ") + ".");
    }
    const auto& ioctls = r.ioctls->ioctls;
    if (!ioctls.empty()) {
        std::size_t neither = 0, anyAccess = 0;
        for (const auto& e : ioctls) {
            neither += e.decoded.method == 3;
            anyAccess += e.decoded.access == 0;
        }
        a.exposure.push_back(std::to_string(ioctls.size()) + " IOCTL code(s) recovered: " + std::to_string(neither) +
                             " METHOD_NEITHER, " + std::to_string(anyAccess) + " FILE_ANY_ACCESS.");
    }

    // ---- top risks
    for (const auto& f : findings.findings) {
        if (a.topRisks.size() >= 5 || f.severity < fnd::Severity::Medium) {
            break; // findings are sorted most severe first
        }
        Assessment::Risk risk;
        risk.severity = fnd::severityName(f.severity);
        risk.confidence = fnd::confidenceName(f.confidence);
        risk.title = f.title;
        risk.ruleId = f.ruleId;
        risk.why = f.description;
        if (!f.evidence.empty() && !f.evidence.front().empty()) {
            risk.function = f.evidence.front().back().function;
        }
        a.topRisks.push_back(std::move(risk));
    }

    // ---- protections and gaps
    bool secureOpen = false, noSecureOpen = false;
    for (const auto& d : dev.devices) {
        if (d.secureOpen() == true) secureOpen = true;
        if (d.secureOpen() == false) noSecureOpen = true;
        if (!d.sddl.empty()) {
            a.protections.push_back("Device access is restricted in code by SDDL " + d.sddl + ".");
        }
        if (d.exclusive == true) {
            a.protections.push_back(d.name.empty() ? "A device is exclusive (one open handle at a time)."
                                                   : d.name + " is exclusive (one open handle at a time).");
        }
    }
    if (secureOpen) {
        a.protections.push_back("FILE_DEVICE_SECURE_OPEN is set, so the device's ACL also applies to its namespace.");
    }
    bool probes = false;
    for (const auto& api : r.kernelApis->apis) {
        if ((api.name == "ProbeForRead" || api.name == "ProbeForWrite") && !api.callers.empty()) {
            probes = true;
        }
    }
    if (probes) {
        a.protections.push_back("Validates user-mode buffers with ProbeForRead/ProbeForWrite.");
    }
    const auto dll = r.image->dllCharacteristics;
    if ((dll & 0x0100) && (dll & 0x0040)) {
        a.protections.push_back("Built with NX and ASLR (DYNAMIC_BASE).");
    }
    if (r.image->signature.hasEmbeddedSignature) {
        a.protections.push_back("Carries an embedded Authenticode signature (" + r.image->signature.verification + ").");
    }

    if (noSecureOpen) {
        a.gaps.push_back("A device is created without FILE_DEVICE_SECURE_OPEN.");
    }
    if (hasRule(findings, "DASA-DEVICE-DEFAULT-ACL")) {
        a.gaps.push_back("A user-mode-openable device has no SDDL in code - its default ACL decides who can open it.");
    }
    if (hasRule(findings, "DASA-METHOD-NEITHER") && !probes) {
        a.gaps.push_back("METHOD_NEITHER IOCTLs with no ProbeForRead/ProbeForWrite anywhere in the driver.");
    }
    if (hasRule(findings, "DASA-ANY-ACCESS")) {
        a.gaps.push_back("IOCTLs that require no read/write access on the handle (FILE_ANY_ACCESS).");
    }
    if (hasRule(findings, "DASA-NO-NX") || hasRule(findings, "DASA-NO-ASLR")) {
        a.gaps.push_back("Missing NX or ASLR image flags.");
    }
    if (hasRule(findings, "DASA-WX-SECTION")) {
        a.gaps.push_back("A section is both writable and executable.");
    }

    // ---- verdict
    const fnd::Finding* taintCritical = nullptr;
    for (const auto& f : findings.findings) {
        if (f.ruleId.rfind("DASA-TAINT", 0) == 0 && f.severity >= fnd::Severity::High) {
            taintCritical = &f;
            break;
        }
    }
    const fnd::Finding* reach = firstRule(findings, "DASA-REACH-CRITICAL");
    if (!reach) reach = firstRule(findings, "DASA-REACH-HIGH");
    const bool openable = !names.empty() || !dev.interfaces.empty();
    if (taintCritical) {
        a.headline = "Request data from user mode reaches a dangerous operation.";
        a.verdict = taintCritical->title + ". " +
                    (openable ? "The device is reachable from user mode, so this is likely exploitable by whoever "
                                "can open it - confirm the data isn't range-checked first and check the device's ACL."
                              : "No user-mode name was recovered, so check how the device can be reached.");
    } else if (reach) {
        a.headline = "Dangerous capabilities are reachable from user requests.";
        a.verdict = reach->title + ". DASA did not trace request data into these calls (see the data-flow notes in "
                                   "the evidence), so they may be fixed-purpose - review whether the request can "
                                   "influence them.";
    } else if (findings.risk.score >= 15) {
        a.headline = "No dangerous capability is exposed, but the attack surface has weaknesses.";
        a.verdict = "The findings concern device security, IOCTL definitions or hardening rather than a dangerous "
                    "operation reachable from a request.";
    } else {
        a.headline = "No significant attack surface was found.";
        a.verdict = "DASA found no dangerous operation reachable from user requests. Static analysis can miss code "
                    "reached through pointers or switch tables - see coverage.";
    }

    // ---- next steps
    if (taintCritical || hasRule(findings, "DASA-TAINT") || hasRule(findings, "DASA-UNPROBED")) {
        a.nextSteps.push_back("Open the Data Flow tab and confirm, for each flow, whether the value is validated "
                              "before it is used.");
    }
    if (reach) {
        a.nextSteps.push_back("Follow the evidence chain of \"" + reach->title +
                              "\" in Control Flow to see which IOCTL case leads there.");
    }
    if (openable && (noSecureOpen || hasRule(findings, "DASA-DEVICE-DEFAULT-ACL"))) {
        a.nextSteps.push_back("Check the device's effective ACL on a test system (e.g. with accesschk or "
                              "WinObj) - if unprivileged users can open it, every reachable issue applies to them.");
    }
    if (hasRule(findings, "DASA-METHOD-NEITHER")) {
        a.nextSteps.push_back("Review each METHOD_NEITHER handler for probing and double fetches of the user "
                              "buffer.");
    }
    a.nextSteps.push_back("Bookmark what you've checked and note conclusions in the Research tabs.");

    // ---- coverage / limits
    for (const auto& n : drv.notes) a.coverage.push_back(n);
    for (const auto& n : r.ioctls->notes) a.coverage.push_back(n);
    for (const auto& n : r.dataflow->notes) a.coverage.push_back(n);
    for (const auto& n : findings.notes) a.coverage.push_back(n);
    std::set<std::string> seen;
    a.coverage.erase(std::remove_if(a.coverage.begin(), a.coverage.end(),
                                    [&](const std::string& s) { return !seen.insert(s).second; }),
                     a.coverage.end());
    return a;
}

} // namespace dasa::analysis
