#include "analysis/report/ReportWriter.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <sstream>

#include <nlohmann/json.hpp>

#include "core/Version.h"
#include "core/ioctl/IoctlCodec.h"

namespace dasa::analysis {

using nlohmann::json;
namespace fnd = core::findings;
namespace sec = core::security;

namespace {

std::string hex(std::uint64_t v, int width = 8) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%0*llX", width, static_cast<unsigned long long>(v));
    return buf;
}

std::string utcNow() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

const char* stepKind(fnd::EvidenceStep::Kind k) {
    using K = fnd::EvidenceStep::Kind;
    switch (k) {
    case K::UserModeName: return "user-mode-name";
    case K::Device: return "device";
    case K::EntryPoint: return "entry-point";
    case K::Ioctl: return "ioctl";
    case K::Function: return "function";
    case K::Call: return "call";
    case K::Instruction: return "instruction";
    case K::Header: return "header";
    case K::Note: break;
    }
    return "note";
}

std::string functionName(const AnalysisResult& r, std::uint64_t rva) {
    const auto* f = r.functions->find(rva);
    return f ? f->name : hex(rva);
}

json buildJson(const AnalysisResult& r) {
    const auto& img = *r.image;
    json j;
    j["schema"] = "dasa-report/1";
    j["generator"] = {{"name", "DASA"}, {"version", core::Version::string()}};
    j["generatedAt"] = utcNow();
    j["file"] = {{"name", img.fileName},
                 {"path", img.path.string()},
                 {"size", img.fileSize},
                 {"md5", img.hashes.md5},
                 {"sha1", img.hashes.sha1},
                 {"sha256", img.hashes.sha256}};

    json sections = json::array();
    for (const auto& s : img.sections) {
        sections.push_back({{"name", s.name},
                            {"virtualAddress", hex(s.virtualAddress)},
                            {"virtualSize", hex(s.virtualSize)},
                            {"rawSize", hex(s.rawSize)},
                            {"characteristics", hex(s.characteristics)},
                            {"flags", s.flags},
                            {"entropy", s.entropy}});
    }
    j["pe"] = {{"machine", img.machineName},
               {"pe32plus", img.is64Bit},
               {"subsystem", img.subsystemName},
               {"imageBase", hex(img.imageBase, 16)},
               {"entryPointRva", hex(img.entryPointRva)},
               {"timestamp", img.timestampUtc},
               {"headerChecksum", hex(img.headerChecksum)},
               {"computedChecksum", hex(img.computedChecksum)},
               {"dllCharacteristics", img.dllCharacteristicFlags},
               {"pdb", img.pdbPath},
               {"sections", sections},
               {"signature",
                {{"embedded", img.signature.hasEmbeddedSignature},
                 {"digestValid", img.signature.digestValid},
                 {"verification", img.signature.verification},
                 {"signers", [&] {
                      json a = json::array();
                      for (const auto& s : img.signature.signers) {
                          a.push_back({{"subject", s.subject}, {"issuer", s.issuer}, {"digest", s.digestAlgorithm}});
                      }
                      return a;
                  }()}}}};

    const auto& d = *r.driver;
    json majors = json::array();
    for (const auto& e : d.majorFunctions) {
        majors.push_back({{"major", e.major},
                          {"name", core::driver::irpMajorName(e.major)},
                          {"handler", hex(e.handler)},
                          {"isFunction", e.handlerIsFunction},
                          {"how", e.how}});
    }
    json queues = json::array();
    for (const auto& q : d.wdfQueues) {
        json cbs = json::array();
        for (const auto& cb : q.callbacks) {
            cbs.push_back({{"name", cb.name}, {"function", hex(cb.function)}});
        }
        queues.push_back({{"createCall", hex(q.createCall)},
                          {"dispatchType", q.dispatchType},
                          {"defaultQueue", q.defaultQueue ? json(*q.defaultQueue) : json(nullptr)},
                          {"callbacks", cbs}});
    }
    json entryChain = json::array();
    for (auto rva : d.entryChain) {
        entryChain.push_back(hex(rva));
    }
    j["driver"] = {{"model", core::driver::modelName(d.model.kind)},
                   {"confidence", core::driver::confidenceName(d.model.confidence)},
                   {"evidence", d.model.evidence},
                   {"driverEntry", d.driverEntry ? json(hex(*d.driverEntry)) : json(nullptr)},
                   {"entryChain", entryChain},
                   {"majorFunctions", majors},
                   {"wdfVersion", d.wdfBind ? json(std::to_string(d.wdfBind->major) + "." +
                                                   std::to_string(d.wdfBind->minor) + "." +
                                                   std::to_string(d.wdfBind->build))
                                             : json(nullptr)},
                   {"wdfQueues", queues},
                   {"notes", d.notes}};

    json ioctls = json::array();
    for (const auto& e : r.ioctls->ioctls) {
        ioctls.push_back({{"code", core::ioctl::hexCode(e.decoded.code)},
                          {"deviceType", core::ioctl::deviceTypeName(e.decoded.deviceType)},
                          {"function", e.decoded.function},
                          {"method", core::ioctl::methodName(e.decoded.method)},
                          {"access", core::ioctl::accessName(e.decoded.access)},
                          {"handler", e.handler},
                          {"comparedIn", hex(e.comparedIn)},
                          {"caseTarget", e.caseTarget ? json(hex(*e.caseTarget)) : json(nullptr)},
                          {"evidence", core::ioctl::evidenceName(e.evidence)}});
    }
    j["ioctls"] = ioctls;

    json devices = json::array();
    for (const auto& x : r.devices->devices) {
        devices.push_back({{"name", x.name},
                           {"api", x.api},
                           {"deviceType", x.deviceType ? json(core::ioctl::deviceTypeName(*x.deviceType)) : json(nullptr)},
                           {"secureOpen", x.secureOpen() ? json(*x.secureOpen()) : json(nullptr)},
                           {"sddl", x.sddl}});
    }
    json links = json::array();
    for (const auto& l : r.devices->symbolicLinks) {
        links.push_back({{"link", l.link}, {"target", l.target}, {"api", l.api}});
    }
    json ifaces = json::array();
    for (const auto& i : r.devices->interfaces) {
        ifaces.push_back({{"guid", i.guid}, {"api", i.api}});
    }
    j["devices"] = {{"deviceObjects", devices},
                    {"symbolicLinks", links},
                    {"interfaces", ifaces},
                    {"nameStrings", r.devices->deviceNameStrings},
                    {"linkStrings", r.devices->linkNameStrings}};

    json apis = json::array();
    for (const auto& a : r.kernelApis->apis) {
        if (a.info.risk == sec::ApiRisk::Info) {
            continue;
        }
        json callers = json::array();
        for (auto c : a.callers) {
            callers.push_back(functionName(r, c));
        }
        apis.push_back({{"name", a.name},
                        {"library", a.library},
                        {"category", sec::categoryName(a.info.category)},
                        {"risk", sec::riskName(a.info.risk)},
                        {"why", a.info.why},
                        {"resolvedAtRuntime", a.resolvedAtRuntime},
                        {"callers", callers},
                        {"reachableFrom", a.reachableFrom}});
    }
    json priv = json::array();
    for (const auto& p : r.kernelApis->privileged) {
        priv.push_back({{"instruction", p.text},
                        {"kind", p.kind},
                        {"rva", hex(p.rva)},
                        {"function", functionName(r, p.function)},
                        {"reachableFrom", p.reachableFrom}});
    }
    j["kernelApis"] = apis;
    j["privilegedInstructions"] = priv;
    j["functionCount"] = r.functions->functions.size();

    json findings = json::array();
    for (const auto& f : r.findings->findings) {
        json chains = json::array();
        for (const auto& chain : f.evidence) {
            json steps = json::array();
            for (const auto& s : chain) {
                steps.push_back({{"kind", stepKind(s.kind)},
                                 {"label", s.label},
                                 {"detail", s.detail},
                                 {"rva", s.rva ? json(hex(*s.rva)) : json(nullptr)}});
            }
            chains.push_back(steps);
        }
        findings.push_back({{"ruleId", f.ruleId},
                            {"title", f.title},
                            {"category", f.category},
                            {"severity", fnd::severityName(f.severity)},
                            {"confidence", fnd::confidenceName(f.confidence)},
                            {"description", f.description},
                            {"recommendation", f.recommendation},
                            {"evidence", chains}});
    }
    json contributions = json::array();
    for (const auto& c : r.findings->risk.contributions) {
        contributions.push_back({{"ruleId", c.ruleId}, {"title", c.title}, {"points", c.points}});
    }
    j["findings"] = findings;
    j["risk"] = {{"score", r.findings->risk.score},
                 {"level", r.findings->risk.level},
                 {"contributions", contributions}};
    return j;
}

// ------------------------------------------------------------------ HTML ----

const char* kCss = R"css(
:root{--bg:#1e1e1e;--panel:#252526;--line:#333337;--text:#dcdcdc;--muted:#9a9a9a;
--crit:#f1706b;--high:#e5a54b;--med:#d8c86a;--low:#7fb2e5;--info:#b0b0b0;--ok:#6cc68a}
@media (prefers-color-scheme: light){:root{--bg:#ffffff;--panel:#f5f6f8;--line:#dfe2e6;--text:#1f2328;
--muted:#57606a;--crit:#c62828;--high:#b45309;--med:#8a6d00;--low:#1d5fa8;--info:#57606a;--ok:#1a7f37}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 "Segoe UI",system-ui,sans-serif}main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 10px;border-bottom:1px solid var(--line);
padding-bottom:6px}h3{font-size:15px;margin:0 0 6px}.muted{color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px;margin:10px 0}
.score{font-size:40px;font-weight:600}table{width:100%;border-collapse:collapse;margin:6px 0}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}code,.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:13px}
.sev{font-weight:600}.Critical{color:var(--crit)}.High{color:var(--high)}.Medium{color:var(--med)}
.Low{color:var(--low)}.Info{color:var(--info)}.Minimal{color:var(--ok)}
ol.chain{margin:6px 0 0;padding-left:22px}ol.chain li{margin:2px 0}
.wrap{overflow-x:auto}
)css";

void row(std::ostringstream& o, std::initializer_list<std::string> cells) {
    o << "<tr>";
    for (const auto& c : cells) {
        o << "<td>" << c << "</td>";
    }
    o << "</tr>";
}

} // namespace

std::string htmlEscape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

std::string reportJson(const AnalysisResult& result, int indent) {
    return buildJson(result).dump(indent);
}

std::string reportHtml(const AnalysisResult& r) {
    const auto& img = *r.image;
    const auto& risk = r.findings->risk;
    const auto e = [](const std::string& s) { return htmlEscape(s); };
    std::ostringstream o;
    o << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
      << "<title>DASA report - " << e(img.fileName) << "</title><style>" << kCss << "</style></head><body><main>";

    o << "<h1>" << e(img.fileName) << "</h1><div class=\"muted mono\">SHA-256 " << e(img.hashes.sha256) << "</div>";
    o << "<div class=\"card\"><span class=\"score " << e(risk.level) << "\">" << risk.score
      << "</span><span class=\"muted\">/100</span> &nbsp;<span class=\"sev " << e(risk.level) << "\">"
      << e(risk.level) << " risk</span><div class=\"muted\">"
      << e(core::driver::modelName(r.driver->model.kind)) << " driver &middot; " << r.functions->functions.size()
      << " functions &middot; " << r.ioctls->ioctls.size() << " IOCTLs &middot; " << r.devices->devices.size()
      << " device objects &middot; " << r.findings->findings.size() << " findings. Generated by DASA "
      << e(core::Version::string()) << " on " << e(utcNow())
      << ". The score is a weighted sum of the findings for triage, not a measure of exploitability.</div></div>";

    o << "<h2>Findings</h2>";
    if (r.findings->findings.empty()) {
        o << "<p class=\"muted\">No findings.</p>";
    }
    for (const auto& f : r.findings->findings) {
        o << "<div class=\"card\"><h3><span class=\"sev " << fnd::severityName(f.severity) << "\">"
          << fnd::severityName(f.severity) << "</span> &middot; " << e(f.title) << "</h3><div class=\"muted\">"
          << e(f.category) << " &middot; " << fnd::confidenceName(f.confidence) << " confidence &middot; <code>"
          << e(f.ruleId) << "</code></div><p>" << e(f.description) << "</p><p><b>Recommendation.</b> "
          << e(f.recommendation) << "</p>";
        int n = 1;
        for (const auto& chain : f.evidence) {
            o << "<div class=\"muted\">Evidence " << n++ << "</div><ol class=\"chain\">";
            for (const auto& s : chain) {
                o << "<li><b>" << e(s.label) << "</b>";
                if (!s.detail.empty()) {
                    o << " <span class=\"muted\">" << e(s.detail) << "</span>";
                }
                if (s.rva) {
                    o << " <code>" << hex(*s.rva) << "</code>";
                }
                o << "</li>";
            }
            o << "</ol>";
        }
        o << "</div>";
    }

    o << "<h2>IOCTLs</h2><div class=\"wrap\"><table><tr><th>Code</th><th>Device type</th><th>Method</th>"
         "<th>Access</th><th>Handler</th><th>Found by</th></tr>";
    for (const auto& x : r.ioctls->ioctls) {
        row(o, {"<code>" + core::ioctl::hexCode(x.decoded.code) + "</code>",
                e(core::ioctl::deviceTypeName(x.decoded.deviceType)), core::ioctl::methodName(x.decoded.method),
                core::ioctl::accessName(x.decoded.access), e(x.handler), core::ioctl::evidenceName(x.evidence)});
    }
    o << "</table></div>";
    if (r.ioctls->ioctls.empty()) {
        o << "<p class=\"muted\">No IOCTL codes recovered.</p>";
    }

    o << "<h2>Devices</h2><div class=\"wrap\"><table><tr><th>Name</th><th>Created by</th><th>Type</th>"
         "<th>Secure open</th><th>SDDL</th></tr>";
    for (const auto& x : r.devices->devices) {
        row(o, {e(x.name.empty() ? "(unnamed / unresolved)" : x.name), e(x.api),
                x.deviceType ? e(core::ioctl::deviceTypeName(*x.deviceType)) : "?",
                x.secureOpen() ? (*x.secureOpen() ? "yes" : "no") : "unknown",
                x.sddl.empty() ? "<span class=\"muted\">default</span>" : "<code>" + e(x.sddl) + "</code>"});
    }
    o << "</table></div>";
    for (const auto& l : r.devices->symbolicLinks) {
        o << "<div><code>" << e(l.link) << "</code>" << (l.target.empty() ? "" : " &rarr; <code>" + e(l.target) + "</code>")
          << " <span class=\"muted\">" << e(l.api) << "</span></div>";
    }

    o << "<h2>Risky kernel APIs</h2><div class=\"wrap\"><table><tr><th>API</th><th>Risk</th><th>Why</th>"
         "<th>Reachable from</th></tr>";
    for (const auto& a : r.kernelApis->apis) {
        if (a.info.risk < sec::ApiRisk::Medium) {
            continue;
        }
        std::string reach;
        for (const auto& x : a.reachableFrom) {
            reach += (reach.empty() ? "" : ", ") + x;
        }
        const std::string riskClass = a.info.risk == sec::ApiRisk::Critical ? "Critical"
                                      : a.info.risk == sec::ApiRisk::High   ? "High"
                                                                            : "Medium";
        row(o, {"<code>" + e(a.name) + "</code>" + (a.resolvedAtRuntime ? " <span class=\"muted\">(runtime)</span>" : ""),
                "<span class=\"sev " + riskClass + "\">" + sec::riskName(a.info.risk) + "</span>", e(a.info.why),
                reach.empty() ? (a.callers.empty() ? "<span class=\"muted\">no call site found</span>" : "<span class=\"muted\">-</span>")
                              : e(reach)});
    }
    o << "</table></div>";
    if (!r.kernelApis->privileged.empty()) {
        o << "<h3>Privileged instructions</h3><ul>";
        for (const auto& p : r.kernelApis->privileged) {
            o << "<li><code>" << e(p.text) << "</code> " << e(p.kind) << " in " << e(functionName(r, p.function))
              << " <code>" << hex(p.rva) << "</code></li>";
        }
        o << "</ul>";
    }

    const auto& d = *r.driver;
    o << "<h2>Driver model</h2><div class=\"card\"><b>" << e(core::driver::modelName(d.model.kind)) << "</b> ("
      << core::driver::confidenceName(d.model.confidence) << " confidence)<ul>";
    for (const auto& ev : d.model.evidence) {
        o << "<li>" << e(ev) << "</li>";
    }
    o << "</ul>";
    if (d.driverEntry) {
        o << "<div>DriverEntry: <code>" << hex(*d.driverEntry) << "</code> <span class=\"muted\">"
          << e(d.driverEntryNote) << "</span></div>";
    }
    o << "</div>";
    if (!d.majorFunctions.empty()) {
        o << "<table><tr><th>IRP</th><th>Handler</th></tr>";
        for (const auto& m : d.majorFunctions) {
            row(o, {core::driver::irpMajorName(m.major), "<code>" + hex(m.handler) + "</code> " + e(functionName(r, m.handler))});
        }
        o << "</table>";
    }

    o << "<h2>File</h2><table>";
    row(o, {"Path", e(img.path.string())});
    row(o, {"Size", std::to_string(img.fileSize) + " bytes"});
    row(o, {"MD5 / SHA-1", "<code>" + e(img.hashes.md5) + "</code><br><code>" + e(img.hashes.sha1) + "</code>"});
    row(o, {"Machine", e(img.machineName) + (img.is64Bit ? " (PE32+)" : " (PE32)")});
    row(o, {"Timestamp", e(img.timestampUtc)});
    row(o, {"Signature", img.signature.hasEmbeddedSignature ? e(img.signature.verification) : "no embedded signature"});
    o << "</table></main></body></html>";
    return o.str();
}

std::int64_t saveAnalysis(core::database::AnalysisDatabase& db, const AnalysisResult& r) {
    core::database::StoredAnalysis a;
    auto& s = a.summary;
    s.filePath = r.image->path.string();
    s.fileName = r.image->fileName;
    s.sha256 = r.image->hashes.sha256;
    s.fileSize = static_cast<std::int64_t>(r.image->fileSize);
    s.model = core::driver::modelName(r.driver->model.kind);
    s.riskScore = r.findings->risk.score;
    s.riskLevel = r.findings->risk.level;
    s.functionCount = static_cast<int>(r.functions->functions.size());
    s.ioctlCount = static_cast<int>(r.ioctls->ioctls.size());
    s.deviceCount = static_cast<int>(r.devices->devices.size());
    s.findingCount = static_cast<int>(r.findings->findings.size());
    for (const auto& f : r.findings->findings) {
        a.findings.push_back({f.ruleId, f.title, fnd::severityName(f.severity), fnd::confidenceName(f.confidence),
                              f.category});
    }
    for (const auto& x : r.ioctls->ioctls) {
        a.ioctls.push_back({x.decoded.code, core::ioctl::methodName(x.decoded.method),
                            core::ioctl::accessName(x.decoded.access), x.handler});
    }
    for (const auto& x : r.kernelApis->apis) {
        if (x.info.risk >= sec::ApiRisk::Medium) {
            a.apis.push_back({x.name, sec::riskName(x.info.risk), !x.reachableFrom.empty()});
        }
    }
    return db.save(a, reportJson(r, -1));
}

} // namespace dasa::analysis
