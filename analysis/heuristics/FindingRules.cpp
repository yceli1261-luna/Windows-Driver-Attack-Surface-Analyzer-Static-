#include "analysis/heuristics/FindingRules.h"

#include <algorithm>
#include <cstdio>
#include <deque>
#include <map>
#include <set>
#include <string_view>

#include <spdlog/spdlog.h>

namespace dasa::analysis {

namespace fnd = core::findings;
namespace sec = core::security;
using fnd::EvidenceChain;
using fnd::EvidenceStep;
using fnd::Finding;
using fnd::FindingConfidence;
using fnd::Severity;
using Step = EvidenceStep::Kind;

namespace {

constexpr std::size_t kMaxChains = 4;

std::string hex(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%08llX", static_cast<unsigned long long>(v));
    return buf;
}

bool startsWith(std::string_view s, std::string_view p) {
    return s.substr(0, p.size()) == p;
}

// Entry points a user-mode program can drive with a request on an open handle.
bool isUserRequestRoot(const std::string& name) {
    return name == "IRP_MJ_DEVICE_CONTROL" || name == "IRP_MJ_READ" || name == "IRP_MJ_WRITE" ||
           startsWith(name, "EvtIoDeviceControl") || startsWith(name, "EvtIoRead") ||
           startsWith(name, "EvtIoWrite") || startsWith(name, "EvtIoDefault");
}

bool isInternalRoot(const std::string& name) {
    return name == "IRP_MJ_INTERNAL_DEVICE_CONTROL" || startsWith(name, "EvtIoInternalDeviceControl");
}

Severity lower(Severity s) {
    return s == Severity::Info ? s : static_cast<Severity>(static_cast<int>(s) - 1);
}

class Rules {
public:
    explicit Rules(const FindingInputs& in) : m_in(in) {
        for (const auto& [name, rva] : in.kernelApis.entryPointFunctions) {
            m_roots[name] = rva;
        }
        for (const auto& l : in.devices.symbolicLinks) {
            if (!l.link.empty()) {
                m_userNames.push_back(l.link);
            }
        }
        for (const auto& d : in.devices.devices) {
            if (!d.name.empty()) {
                m_userNames.push_back(d.name);
            }
        }
        m_exposed = !m_userNames.empty() || !in.devices.interfaces.empty();
        for (const auto& u : in.kernelApis.apis) {
            if ((u.name == "ProbeForRead" || u.name == "ProbeForWrite") && !u.callers.empty()) {
                m_probes = true;
            }
        }
    }

    std::vector<Finding> run() {
        reachability();
        dataFlow();
        annotateReachWithDataFlow();
        deviceSecurity();
        ioctlProperties();
        capabilities();
        hardening();
        return std::move(m_findings);
    }

private:
    std::string fnName(std::uint64_t rva) const {
        const auto* f = m_in.functions.find(rva);
        return f ? f->name : hex(rva);
    }

    // Shortest call path root -> target (both included), over direct calls.
    std::vector<std::uint64_t> callPath(std::uint64_t root, std::uint64_t target) const {
        std::map<std::uint64_t, std::uint64_t> parent{{root, root}};
        std::deque<std::uint64_t> work{root};
        while (!work.empty()) {
            const std::uint64_t cur = work.front();
            work.pop_front();
            if (cur == target) {
                std::vector<std::uint64_t> path{cur};
                for (std::uint64_t p = cur; p != root;) {
                    p = parent[p];
                    path.push_back(p);
                }
                std::reverse(path.begin(), path.end());
                return path;
            }
            const auto* fn = m_in.functions.find(cur);
            if (fn == nullptr) {
                continue;
            }
            for (const auto& call : fn->calls) {
                if (call.target && parent.emplace(*call.target, cur).second) {
                    work.push_back(*call.target);
                }
            }
        }
        return {};
    }

    EvidenceStep userNameStep() const {
        EvidenceStep s;
        s.kind = Step::UserModeName;
        if (!m_userNames.empty()) {
            s.label = m_userNames.front();
            s.detail = m_userNames.size() > 1 ? "and " + std::to_string(m_userNames.size() - 1) + " other name(s)"
                                              : "user-mode programs open the device by this name";
        } else if (!m_in.devices.interfaces.empty()) {
            s.label = "device interface " + m_in.devices.interfaces.front().guid;
            s.detail = "user-mode programs open the device through its interface";
        } else {
            s.label = "(no user-mode name recovered)";
            s.detail = "the device may still be reachable (PnP stack, name built at runtime)";
        }
        return s;
    }

    // The IOCTL codes compared in the function closest to the call on the
    // path - the comparison that gates the call. (Codes compared further up
    // are usually other cases of the same dispatch.)
    std::optional<EvidenceStep> ioctlStep(const std::vector<std::uint64_t>& path) const {
        for (auto it = path.rbegin(); it != path.rend(); ++it) {
            std::vector<const core::ioctl::ExtractedIoctl*> codes;
            for (const auto& e : m_in.ioctls.ioctls) {
                if (e.comparedIn == *it) {
                    codes.push_back(&e);
                }
            }
            if (codes.empty()) {
                continue;
            }
            EvidenceStep s;
            s.kind = Step::Ioctl;
            std::string list;
            for (std::size_t i = 0; i < codes.size() && i < 3; ++i) {
                list += (i ? ", " : "") + core::ioctl::hexCode(codes[i]->decoded.code);
            }
            if (codes.size() > 3) {
                list += " and " + std::to_string(codes.size() - 3) + " more";
            }
            s.label = (codes.size() == 1 ? "IOCTL " : "IOCTLs ") + list;
            s.detail = "compared in " + fnName(*it) + " on the path to the call";
            s.rva = codes.front()->at;
            s.function = *it;
            return s;
        }
        return std::nullopt;
    }

    EvidenceChain chainTo(const std::string& rootName, std::uint64_t caller, EvidenceStep last) const {
        EvidenceChain chain;
        chain.push_back(userNameStep());
        const std::uint64_t root = m_roots.at(rootName);
        EvidenceStep entry;
        entry.kind = Step::EntryPoint;
        entry.label = rootName;
        entry.detail = fnName(root);
        entry.rva = root;
        entry.function = root;
        chain.push_back(entry);
        const auto path = callPath(root, caller);
        if (auto io = ioctlStep(path)) {
            chain.push_back(*io);
        }
        for (std::size_t i = 1; i < path.size(); ++i) {
            EvidenceStep f;
            f.kind = Step::Function;
            f.label = fnName(path[i]);
            f.detail = "called from " + fnName(path[i - 1]);
            f.rva = path[i];
            f.function = path[i];
            chain.push_back(f);
        }
        chain.push_back(std::move(last));
        return chain;
    }

    static std::string recommendationFor(sec::ApiCategory c) {
        switch (c) {
        case sec::ApiCategory::PhysicalMemory:
        case sec::ApiCategory::Hardware:
            return "Don't expose physical memory, port or bus access to user requests. If it is needed, restrict "
                   "the device to administrators (IoCreateDeviceSecure / INF SDDL) and validate addresses and "
                   "lengths against a fixed allow-list in the driver.";
        case sec::ApiCategory::VirtualMemory:
        case sec::ApiCategory::Process:
        case sec::ApiCategory::Token:
            return "Validate every pointer, length, PID and handle that comes from the request, require "
                   "privileged callers (check the requestor mode and access), and avoid operating on arbitrary "
                   "processes on behalf of user mode.";
        case sec::ApiCategory::DriverLoading:
            return "Never let user requests choose images to load or system settings to change.";
        default:
            return "Check that the request's input can't control this call's arguments, and restrict who can "
                   "open the device.";
        }
    }

    // ---------------------------------------------------- reachability ----

    void reachability() {
        for (const auto& api : m_in.kernelApis.apis) {
            if (api.info.risk < sec::ApiRisk::High || api.callers.empty()) {
                continue;
            }
            const std::string label = api.resolvedAtRuntime ? api.name + " (resolved at runtime)" : api.name;
            addReachFinding(label, api.info.risk, api.info.category, api.info.why, api.reachableFrom, api.callers,
                            [&](std::uint64_t caller) {
                                EvidenceStep s;
                                s.kind = Step::Call;
                                s.label = label;
                                s.detail = "called in " + fnName(caller);
                                s.function = caller;
                                const auto* fn = m_in.functions.find(caller);
                                if (fn) {
                                    for (const auto& c : fn->calls) {
                                        if (!c.importName.empty() &&
                                            std::string_view(c.importName).ends_with("!" + api.name)) {
                                            s.rva = c.rva;
                                            break;
                                        }
                                    }
                                }
                                return s;
                            });
        }
        for (const auto& p : m_in.kernelApis.privileged) {
            if (p.risk < sec::ApiRisk::High) {
                continue;
            }
            addReachFinding(p.kind + " (" + p.text + ")", p.risk, sec::ApiCategory::Hardware,
                            "Privileged instruction executed directly on the CPU", p.reachableFrom, {p.function},
                            [&](std::uint64_t) {
                                EvidenceStep s;
                                s.kind = Step::Instruction;
                                s.label = p.text;
                                s.detail = p.kind + " at " + hex(p.rva);
                                s.rva = p.rva;
                                s.function = p.function;
                                return s;
                            });
        }
    }

    template <typename MakeLast>
    void addReachFinding(const std::string& what, sec::ApiRisk risk, sec::ApiCategory category,
                         const std::string& why, const std::set<std::string>& reachableFrom,
                         const std::vector<std::uint64_t>& callers, MakeLast makeLast) {
        std::vector<std::string> userRoots, internalRoots;
        for (const auto& r : reachableFrom) {
            if (m_roots.count(r) == 0) {
                continue;
            }
            if (isUserRequestRoot(r)) {
                userRoots.push_back(r);
            } else if (isInternalRoot(r)) {
                internalRoots.push_back(r);
            }
        }
        const bool fromUser = !userRoots.empty();
        if (!fromUser && internalRoots.empty()) {
            return;
        }
        const auto& roots = fromUser ? userRoots : internalRoots;

        Finding f;
        f.category = "Exposed capability";
        f.confidence = FindingConfidence::Medium;
        if (fromUser) {
            f.ruleId = risk == sec::ApiRisk::Critical ? "DASA-REACH-CRITICAL" : "DASA-REACH-HIGH";
            f.severity = risk == sec::ApiRisk::Critical ? Severity::Critical : Severity::High;
            if (!m_exposed) {
                f.severity = lower(f.severity);
            }
            f.title = what + " is reachable from " + roots.front() +
                      (roots.size() > 1 ? " (+" + std::to_string(roots.size() - 1) + ")" : "");
            f.description = why + ". A program that can open the device reaches this " +
                            std::string(category == sec::ApiCategory::Hardware ? "instruction" : "call") +
                            " by sending a request handled by " + roots.front() +
                            ". This finding is about reachability; whether the request's data controls the "
                            "arguments is in the data-flow note in the evidence and in any DASA-TAINT finding for "
                            "the same call.";
            if (!m_exposed) {
                f.description += " No user-mode name or interface for the device was recovered, so the severity "
                                 "is lowered one step.";
            }
        } else {
            f.ruleId = "DASA-REACH-INTERNAL";
            f.severity = risk == sec::ApiRisk::Critical ? Severity::Medium : Severity::Low;
            f.title = what + " is reachable from " + roots.front() + " (kernel-mode senders)";
            f.description = why + ". Reachable from internal device control, which only kernel-mode components "
                                  "can send - exposure depends on what sits above this driver.";
        }
        f.recommendation = recommendationFor(category);

        for (const auto& root : roots) {
            for (std::uint64_t caller : callers) {
                if (f.evidence.size() >= kMaxChains) {
                    break;
                }
                if (callPath(m_roots.at(root), caller).empty()) {
                    continue;
                }
                f.evidence.push_back(chainTo(root, caller, makeLast(caller)));
            }
        }
        m_findings.push_back(std::move(f));
    }


    // ------------------------------------------------------- data flow ----

    static Severity fromFlow(core::dataflow::Severity s) {
        switch (s) {
        case core::dataflow::Severity::Critical: return Severity::Critical;
        case core::dataflow::Severity::High: return Severity::High;
        case core::dataflow::Severity::Medium: break;
        }
        return Severity::Medium;
    }

    static std::string flowRuleId(const core::dataflow::TaintFlow& f) {
        using K = core::dataflow::SinkKind;
        switch (f.kind) {
        case K::ApiArgument: return "DASA-TAINT-API";
        case K::Instruction: return "DASA-TAINT-INSTRUCTION";
        case K::MemoryWrite: break;
        case K::MemoryRead: {
            const bool userPointerOnly =
                !f.operands.empty() && f.operands.front().labels == core::dataflow::kUserPointer;
            return userPointerOnly ? "DASA-UNPROBED-USER-POINTER" : "DASA-TAINT-READ";
        }
        }
        const bool userPointerOnly = !f.operands.empty() && f.operands.front().labels == core::dataflow::kUserPointer;
        return userPointerOnly ? "DASA-UNPROBED-USER-POINTER" : "DASA-TAINT-WRITE";
    }

    static std::string flowTitle(const core::dataflow::TaintFlow& f) {
        using K = core::dataflow::SinkKind;
        std::string names;
        for (const auto& o : f.operands) {
            names += (names.empty() ? "" : ", ") + o.name;
        }
        switch (f.kind) {
        case K::ApiArgument: return "Request data controls " + names + " of " + f.sink;
        case K::Instruction: return "Request data reaches " + f.sink + " (" + names + ")";
        case K::MemoryWrite:
            return flowRuleId(f) == "DASA-UNPROBED-USER-POINTER" ? "Write through an unprobed user-mode pointer"
                                                                 : "Write to an address taken from the request";
        case K::MemoryRead:
            return flowRuleId(f) == "DASA-UNPROBED-USER-POINTER" ? "Read through an unprobed user-mode pointer"
                                                                 : "Read from an address taken from the request";
        }
        return f.sink;
    }

    static std::string flowRecommendation(const core::dataflow::TaintFlow& f) {
        using K = core::dataflow::SinkKind;
        if (flowRuleId(f) == "DASA-UNPROBED-USER-POINTER") {
            return "Call ProbeForRead/ProbeForWrite on the pointer inside __try/__except before touching it, or "
                   "use METHOD_BUFFERED so the I/O manager copies the data. Capture the data once to avoid "
                   "double-fetch races.";
        }
        switch (f.kind) {
        case K::ApiArgument:
            return "Don't pass request data to this API unchecked: validate addresses and lengths against fixed, "
                   "driver-owned ranges (an allow-list), check lengths against the real buffer sizes, and "
                   "restrict the device to administrators.";
        case K::Instruction:
            return "Never let a request choose MSR numbers, ports or register values. Remove the capability or "
                   "limit it to a fixed allow-list, and restrict the device to administrators.";
        case K::MemoryWrite:
        case K::MemoryRead:
            break;
        }
        return "Don't use addresses or offsets from the request to access kernel memory. Pass offsets into a "
               "driver-owned buffer and bound-check them, or redesign the interface.";
    }

    void dataFlow() {
        for (const auto& flow : m_in.dataflow.flows) {
            const bool fromUser = isUserRequestRoot(flow.entry);
            if (!fromUser && !isInternalRoot(flow.entry)) {
                continue;
            }
            Finding f;
            f.ruleId = flowRuleId(flow);
            f.category = "Input handling";
            f.severity = fromFlow(flow.severity);
            const bool lengthsOnly = std::all_of(flow.operands.begin(), flow.operands.end(), [](const auto& o) {
                return o.labels == core::dataflow::kUserLength;
            });
            f.confidence = lengthsOnly ? FindingConfidence::Medium : FindingConfidence::High;
            f.title = flowTitle(flow);
            f.description = flow.impact + ".";
            for (const auto& o : flow.operands) {
                f.description += " " + o.name + " comes from " + (o.source.empty() ? "request data" : o.source) +
                                 (o.sourceAt ? " (read at " + hex(o.sourceAt) + ")" : "") + ".";
            }
            f.description += " DASA follows the data through registers, stack slots and direct calls; it doesn't "
                             "recognise range checks, so confirm whether the value is validated before this point.";
            if (!fromUser) {
                f.severity = lower(lower(f.severity));
                f.title += " (kernel-mode senders)";
                f.description += " The handler is internal device control, which only kernel-mode components can "
                                 "send.";
            } else if (!m_exposed) {
                f.severity = lower(f.severity);
                f.description += " No user-mode name or interface for the device was recovered, so the severity "
                                 "is lowered one step.";
            }
            if (flow.requestorModeChecked) {
                f.severity = lower(f.severity);
                f.confidence = FindingConfidence::Low;
                f.description += " The handler reads Irp->RequestorMode, so it may accept this data only from "
                                 "kernel-mode callers; DASA can't tell whether that check guards this path, so the "
                                 "severity is lowered one step.";
            }
            f.recommendation = flowRecommendation(flow);

            EvidenceChain chain;
            chain.push_back(userNameStep());
            if (!flow.path.empty()) {
                EvidenceStep entry;
                entry.kind = Step::EntryPoint;
                entry.label = flow.entry;
                entry.detail = fnName(flow.path.front());
                entry.rva = flow.path.front();
                entry.function = flow.path.front();
                chain.push_back(entry);
            }
            if (!flow.ioctls.empty()) {
                EvidenceStep io;
                io.kind = Step::Ioctl;
                std::string list;
                for (std::size_t i = 0; i < flow.ioctls.size() && i < 3; ++i) {
                    list += (i ? ", " : "") + core::ioctl::hexCode(flow.ioctls[i]);
                }
                if (flow.ioctls.size() > 3) {
                    list += " and " + std::to_string(flow.ioctls.size() - 3) + " more";
                }
                io.label = (flow.ioctls.size() == 1 ? "IOCTL " : "IOCTLs ") + list;
                io.detail = flow.ioctlsExact ? "its case branch leads here" : "compared on the path (case not resolved)";
                chain.push_back(io);
            }
            for (const auto& o : flow.operands) {
                EvidenceStep src;
                src.kind = Step::DataSource;
                src.label = o.source.empty() ? "request data" : o.source;
                src.detail = "becomes " + o.name + " (" + core::dataflow::describeLabels(o.labels) + ")";
                if (o.sourceAt) {
                    src.rva = o.sourceAt;
                }
                chain.push_back(src);
            }
            for (std::size_t i = 1; i < flow.path.size(); ++i) {
                EvidenceStep fn;
                fn.kind = Step::Function;
                fn.label = fnName(flow.path[i]);
                fn.detail = "called from " + fnName(flow.path[i - 1]) + " with the data";
                fn.rva = flow.path[i];
                fn.function = flow.path[i];
                chain.push_back(fn);
            }
            EvidenceStep last;
            last.kind = flow.kind == core::dataflow::SinkKind::ApiArgument ? Step::Call : Step::Instruction;
            last.label = flow.kind == core::dataflow::SinkKind::ApiArgument
                             ? flow.sink
                             : flow.sink + " (" + core::dataflow::sinkKindName(flow.kind) + ")";
            last.detail = flow.impact + ", in " + fnName(flow.function);
            last.rva = flow.at;
            last.function = flow.function;
            chain.push_back(last);
            f.evidence.push_back(std::move(chain));
            m_findings.push_back(std::move(f));
        }
    }

    static std::string compactHex(std::int64_t v) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
        return buf;
    }

    // Adds what data flow found at each reachable call to DASA-REACH-*.
    void annotateReachWithDataFlow() {
        for (auto& f : m_findings) {
            if (f.ruleId.rfind("DASA-REACH", 0) != 0) {
                continue;
            }
            for (auto& chain : f.evidence) {
                if (chain.empty() || !chain.back().rva) {
                    continue;
                }
                const std::uint64_t at = *chain.back().rva;
                EvidenceStep note;
                note.kind = Step::Note;
                note.rva = at;
                const auto flow = std::find_if(m_in.dataflow.flows.begin(), m_in.dataflow.flows.end(),
                                               [&](const auto& x) { return x.at == at; });
                const auto checked = std::find_if(m_in.dataflow.checkedCalls.begin(), m_in.dataflow.checkedCalls.end(),
                                                  [&](const auto& x) { return x.at == at; });
                if (flow != m_in.dataflow.flows.end()) {
                    note.label = "Data flow: request data reaches this operation";
                    note.detail = "see " + flowRuleId(*flow) + " - " + flowTitle(*flow);
                } else if (checked != m_in.dataflow.checkedCalls.end()) {
                    std::string args;
                    bool allConstant = true;
                    for (const auto& a : checked->args) {
                        using AK = core::dataflow::CheckedCall::Arg::Kind;
                        args += (args.empty() ? "" : ", ") + a.name + " = " +
                                (a.kind == AK::Constant ? compactHex(a.value) : "not traced");
                        allConstant = allConstant && a.kind == AK::Constant;
                    }
                    note.label = allConstant ? "Data flow: the arguments are constants" : "Data flow: no request data found in the arguments";
                    note.detail = args + (allConstant ? " - the request can't choose them" : "");
                } else {
                    continue;
                }
                chain.push_back(std::move(note));
            }
        }
    }

    // ------------------------------------------------- device security ----

    EvidenceStep deviceStep(const core::driver::DeviceObjectInfo& d) const {
        EvidenceStep s;
        s.kind = Step::Device;
        s.label = d.name.empty() ? "(unnamed device)" : d.name;
        s.detail = d.api + " in " + fnName(d.inFunction);
        s.rva = d.at;
        s.function = d.inFunction;
        return s;
    }

    void deviceSecurity() {
        for (const auto& d : m_in.devices.devices) {
            if (d.name.empty()) {
                continue;
            }
            if (d.secureOpen() == std::optional<bool>(false)) {
                Finding f;
                f.ruleId = "DASA-DEVICE-NO-SECURE-OPEN";
                f.title = d.name + " is created without FILE_DEVICE_SECURE_OPEN";
                f.category = "Device security";
                f.severity = Severity::Medium;
                f.confidence = FindingConfidence::High;
                f.description = "Without FILE_DEVICE_SECURE_OPEN the I/O manager doesn't apply the device's "
                                "security descriptor to opens of names below it (e.g. " + d.name +
                                "\\anything), so a caller denied by the device's ACL may still open it that "
                                "way unless the driver checks the file name itself.";
                f.recommendation = "Set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics (IoCreateDevice) or via "
                                   "WdfDeviceInitSetCharacteristics.";
                EvidenceStep chars;
                chars.kind = Step::Note;
                chars.label = "DeviceCharacteristics = " + core::ioctl::hexCode(d.characteristics.value_or(0));
                chars.detail = "FILE_DEVICE_SECURE_OPEN (0x100) not set";
                f.evidence.push_back({deviceStep(d), chars});
                m_findings.push_back(std::move(f));
            }
            const bool linked = std::any_of(m_in.devices.symbolicLinks.begin(), m_in.devices.symbolicLinks.end(),
                                             [&](const auto& l) { return l.target == d.name || l.target.empty(); });
            if (d.sddl.empty() && linked) {
                Finding f;
                f.ruleId = "DASA-DEVICE-DEFAULT-ACL";
                f.title = d.name + " has a user-mode link and no SDDL in code";
                f.category = "Device security";
                f.severity = Severity::Medium;
                f.confidence = FindingConfidence::Medium;
                f.description = "The device gets the default security descriptor for its type and is exposed "
                                "through a symbolic link, which commonly lets non-administrators open it. A "
                                "security setting in the driver's INF or registry can still restrict it - that "
                                "isn't visible in the binary, hence medium confidence.";
                f.recommendation = "Create the device with IoCreateDeviceSecure (or WdfDeviceInitAssignSDDLString) "
                                   "and an SDDL that grants access only to the intended callers.";
                EvidenceChain chain{deviceStep(d)};
                for (const auto& l : m_in.devices.symbolicLinks) {
                    if (l.target == d.name || l.target.empty()) {
                        EvidenceStep s;
                        s.kind = Step::UserModeName;
                        s.label = l.link;
                        s.detail = l.api + " in " + fnName(l.inFunction);
                        s.rva = l.at;
                        s.function = l.inFunction;
                        chain.push_back(s);
                    }
                }
                f.evidence.push_back(std::move(chain));
                m_findings.push_back(std::move(f));
            }
        }
        for (const auto& l : m_in.devices.symbolicLinks) {
            if (l.api == "IoCreateUnprotectedSymbolicLink") {
                Finding f;
                f.ruleId = "DASA-UNPROTECTED-SYMLINK";
                f.title = "Unprotected symbolic link " + (l.link.empty() ? std::string("(name not resolved)") : l.link);
                f.category = "Device security";
                f.severity = Severity::Medium;
                f.confidence = FindingConfidence::High;
                f.description = "IoCreateUnprotectedSymbolicLink creates a link that other components can delete "
                                "or redirect.";
                f.recommendation = "Use IoCreateSymbolicLink.";
                EvidenceStep s;
                s.kind = Step::UserModeName;
                s.label = l.link;
                s.detail = l.api + " in " + fnName(l.inFunction);
                s.rva = l.at;
                s.function = l.inFunction;
                f.evidence.push_back({s});
                m_findings.push_back(std::move(f));
            }
        }
    }

    // ----------------------------------------------- IOCTL properties ----

    EvidenceChain ioctlChain(const core::ioctl::ExtractedIoctl& e) const {
        EvidenceStep io;
        io.kind = Step::Ioctl;
        io.label = core::ioctl::hexCode(e.decoded.code);
        io.detail = std::string(core::ioctl::methodName(e.decoded.method)) + ", " +
                    core::ioctl::accessName(e.decoded.access) + " (" + core::ioctl::evidenceName(e.evidence) + ")";
        io.rva = e.at;
        io.function = e.comparedIn;
        EvidenceStep h;
        h.kind = Step::EntryPoint;
        h.label = e.handler;
        h.detail = fnName(e.handlerFunction);
        h.rva = e.handlerFunction;
        h.function = e.handlerFunction;
        EvidenceChain c{h, io};
        if (e.caseTarget) {
            EvidenceStep t;
            t.kind = Step::Function;
            t.label = "case code at " + hex(*e.caseTarget);
            t.detail = "in " + fnName(e.comparedIn);
            t.rva = *e.caseTarget;
            t.function = e.comparedIn;
            c.push_back(t);
        }
        return c;
    }

    void ioctlProperties() {
        std::vector<const core::ioctl::ExtractedIoctl*> neither, anyAccess;
        bool neitherTracked = false;
        for (const auto& e : m_in.ioctls.ioctls) {
            if (e.decoded.isMethodNeither()) {
                neither.push_back(&e);
                neitherTracked |= e.evidence == core::ioctl::IoctlEvidence::TrackedCompare;
            }
            if (e.decoded.isAnyAccess()) {
                anyAccess.push_back(&e);
            }
        }
        if (!neither.empty()) {
            Finding f;
            f.ruleId = "DASA-METHOD-NEITHER";
            f.title = std::to_string(neither.size()) + " METHOD_NEITHER IOCTL" + (neither.size() > 1 ? "s" : "") +
                      (m_probes ? "" : ", and the driver never calls ProbeForRead/ProbeForWrite");
            f.category = "Input handling";
            f.severity = m_probes ? Severity::Medium : Severity::High;
            f.confidence = neitherTracked ? FindingConfidence::High : FindingConfidence::Medium;
            f.description = "METHOD_NEITHER hands the driver the caller's raw user-mode pointers "
                            "(Type3InputBuffer, UserBuffer). Each must be probed and accessed under "
                            "try/except, at the right IRQL, in the caller's context." +
                            std::string(m_probes ? "" : " No ProbeForRead or ProbeForWrite call was found anywhere "
                                                        "in the driver.");
            f.recommendation = "Use METHOD_BUFFERED or the direct methods where possible; otherwise probe and "
                               "capture every user buffer before use.";
            for (const auto* e : neither) {
                if (f.evidence.size() >= kMaxChains) {
                    break;
                }
                f.evidence.push_back(ioctlChain(*e));
            }
            m_findings.push_back(std::move(f));
        }
        if (!anyAccess.empty() && m_exposed) {
            Finding f;
            f.ruleId = "DASA-ANY-ACCESS";
            f.title = std::to_string(anyAccess.size()) + " IOCTL" + (anyAccess.size() > 1 ? "s" : "") +
                      " accept any handle (FILE_ANY_ACCESS)";
            f.category = "Input handling";
            f.severity = Severity::Low;
            f.confidence = FindingConfidence::High;
            f.description = "FILE_ANY_ACCESS IOCTLs are dispatched for any open handle, even one opened with no "
                            "read or write access, so the device's ACL is the only gate.";
            f.recommendation = "Require FILE_READ_ACCESS / FILE_WRITE_ACCESS for IOCTLs that read or change state.";
            for (const auto* e : anyAccess) {
                if (f.evidence.size() >= kMaxChains) {
                    break;
                }
                f.evidence.push_back(ioctlChain(*e));
            }
            m_findings.push_back(std::move(f));
        }
    }

    // ----------------------------------------------------- capabilities ----

    void capabilities() {
        for (const auto& api : m_in.kernelApis.apis) {
            if (api.resolvedAtRuntime && api.info.risk >= sec::ApiRisk::Medium) {
                Finding f;
                f.ruleId = "DASA-RUNTIME-RESOLVED";
                f.title = api.name + " is resolved at runtime";
                f.category = "Capability";
                f.severity = api.info.risk >= sec::ApiRisk::High ? Severity::Medium : Severity::Low;
                f.confidence = FindingConfidence::High;
                f.description = "The driver looks " + api.name + " up with MmGetSystemRoutineAddress instead of "
                                "importing it, so it doesn't appear in the import table. " + api.info.why + ".";
                f.recommendation = "Review why the routine is resolved dynamically.";
                for (auto caller : api.callers) {
                    EvidenceStep s;
                    s.kind = Step::Call;
                    s.label = "MmGetSystemRoutineAddress(\"" + api.name + "\")";
                    s.detail = "in " + fnName(caller);
                    s.function = caller;
                    s.rva = caller;
                    f.evidence.push_back({s});
                }
                m_findings.push_back(std::move(f));
            }
        }
        std::vector<const sec::ApiUse*> callbacks;
        for (const auto& api : m_in.kernelApis.apis) {
            if (api.info.category == sec::ApiCategory::Callbacks && api.info.risk >= sec::ApiRisk::Medium &&
                !api.callers.empty()) {
                callbacks.push_back(&api);
            }
        }
        if (!callbacks.empty()) {
            Finding f;
            f.ruleId = "DASA-SYSTEM-CALLBACKS";
            f.title = "Registers system-wide callbacks";
            f.category = "Capability";
            f.severity = Severity::Info;
            f.confidence = FindingConfidence::High;
            f.description = "The driver observes or filters system-wide activity (process/thread/image/registry/"
                            "handle events). Expected for security products; notable otherwise.";
            for (const auto* api : callbacks) {
                EvidenceStep s;
                s.kind = Step::Call;
                s.label = api->name;
                s.detail = "called in " + fnName(api->callers.front());
                s.function = api->callers.front();
                f.evidence.push_back({s});
            }
            m_findings.push_back(std::move(f));
        }
        for (const auto& api : m_in.kernelApis.apis) {
            if (api.imported && api.info.risk == sec::ApiRisk::Critical && api.callers.empty()) {
                Finding f;
                f.ruleId = "DASA-UNCALLED-CRITICAL-IMPORT";
                f.title = api.name + " is imported but no call site was found";
                f.category = "Capability";
                f.severity = Severity::Low;
                f.confidence = FindingConfidence::Low;
                f.description = api.info.why + ". No direct call was found; it may be called through a "
                                "function pointer or from code DASA didn't reach.";
                f.recommendation = "Check how the import is used.";
                EvidenceStep s;
                s.kind = Step::Header;
                s.label = api.library + "!" + api.name;
                s.detail = "import";
                f.evidence.push_back({s});
                m_findings.push_back(std::move(f));
            }
        }
    }

    // -------------------------------------------------------- hardening ----

    void hardening() {
        const auto& img = m_in.image;
        for (const auto& s : img.sections) {
            if (s.isExecutable() && s.isWritable()) {
                Finding f;
                f.ruleId = "DASA-WX-SECTION";
                f.title = "Section " + s.name + " is writable and executable";
                f.category = "Hardening";
                f.severity = Severity::Medium;
                f.confidence = FindingConfidence::High;
                f.description = "Writable+executable memory lets a memory-corruption bug become code execution, "
                                "and is incompatible with HVCI (memory integrity).";
                f.recommendation = "Remove the writable or the executable attribute.";
                EvidenceStep e;
                e.kind = Step::Header;
                e.label = s.name;
                e.detail = "characteristics " + core::ioctl::hexCode(s.characteristics);
                f.evidence.push_back({e});
                m_findings.push_back(std::move(f));
            }
        }
        auto headerFinding = [&](const char* id, const std::string& title, Severity sev, const std::string& desc,
                                 const std::string& rec, const std::string& evidence) {
            Finding f;
            f.ruleId = id;
            f.title = title;
            f.category = "Hardening";
            f.severity = sev;
            f.confidence = FindingConfidence::High;
            f.description = desc;
            f.recommendation = rec;
            EvidenceStep e;
            e.kind = Step::Header;
            e.label = evidence;
            f.evidence.push_back({e});
            m_findings.push_back(std::move(f));
        };
        const std::string dllChars = "DllCharacteristics = " + core::ioctl::hexCode(img.dllCharacteristics);
        if ((img.dllCharacteristics & 0x0100) == 0) {
            headerFinding("DASA-NO-NX", "Not marked NX compatible", Severity::Low,
                          "IMAGE_DLLCHARACTERISTICS_NX_COMPAT is clear; memory integrity (HVCI) expects drivers "
                          "to be NX compatible.",
                          "Link with /NXCOMPAT and keep code and data in separate sections.", dllChars);
        }
        if ((img.dllCharacteristics & 0x0040) == 0) {
            headerFinding("DASA-NO-ASLR", "Not marked DYNAMIC_BASE (ASLR)", Severity::Low,
                          "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is clear.", "Link with /DYNAMICBASE.", dllChars);
        }
        if (!img.signature.hasEmbeddedSignature) {
            headerFinding("DASA-NO-EMBEDDED-SIGNATURE", "No embedded signature", Severity::Info,
                          "The file carries no Authenticode signature. Windows drivers can also be catalog-signed, "
                          "which this check can't see; an unsigned driver won't load with signature enforcement on.",
                          "Verify how the driver is signed.", "security directory empty");
        }
    }

    const FindingInputs& m_in;
    std::map<std::string, std::uint64_t> m_roots;
    std::vector<std::string> m_userNames;
    bool m_exposed = false;
    bool m_probes = false;
    std::vector<Finding> m_findings;
};

} // namespace

fnd::FindingsReport generateFindings(const FindingInputs& in) {
    fnd::FindingsReport report;
    report.findings = Rules(in).run();
    std::stable_sort(report.findings.begin(), report.findings.end(), [](const Finding& a, const Finding& b) {
        if (a.severity != b.severity) {
            return a.severity > b.severity;
        }
        return a.confidence > b.confidence;
    });
    report.risk = fnd::scoreFindings(report.findings);
    if (in.driver.majorFunctions.empty() && in.driver.wdfQueues.empty()) {
        report.notes.push_back("No request handlers were recovered, so findings that depend on reachability "
                               "from user requests could not be produced.");
    }
    spdlog::info("Findings for {}: {} findings, risk {}/100 ({})", in.image.fileName, report.findings.size(),
                 report.risk.score, report.risk.level);
    return report;
}

} // namespace dasa::analysis
