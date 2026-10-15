#include "core/security/KernelApiAnalyzer.h"

#include <algorithm>
#include <deque>
#include <string_view>
#include <unordered_map>

#include <spdlog/spdlog.h>

#include "core/driver/ValueTracker.h"
#include "core/pe/ImageStrings.h"

namespace dasa::core::security {

using disasm::Instruction;
using disasm::Operand;
using disasm::Reg;
using driver::TrackerState;
using driver::Value;
using functions::Function;
using Kind = Value::Kind;

int KernelApiAnalysis::countAtLeast(ApiRisk r) const {
    int n = 0;
    for (const auto& a : apis) {
        n += static_cast<int>(a.info.risk) >= static_cast<int>(r) ? 1 : 0;
    }
    for (const auto& p : privileged) {
        n += static_cast<int>(p.risk) >= static_cast<int>(r) ? 1 : 0;
    }
    return n;
}

namespace {

std::string_view functionPart(std::string_view importName) {
    const auto bang = importName.rfind('!');
    return bang == std::string_view::npos ? importName : importName.substr(bang + 1);
}

// --------------------------------------------------------- entry points ----

using Roots = std::vector<std::pair<std::string, std::uint64_t>>;

Roots collectRoots(const functions::FunctionSet& set, const driver::DriverAnalysis& d) {
    Roots roots;
    auto add = [&](std::string name, std::uint64_t rva) {
        if (set.find(rva) != nullptr) {
            roots.emplace_back(std::move(name), rva);
        }
    };
    if (d.driverEntry) {
        add("DriverEntry", *d.driverEntry);
    }
    for (const auto& e : d.majorFunctions) {
        add(driver::irpMajorName(e.major), e.handler);
    }
    for (const auto& w : d.driverObjectWrites) {
        if (w.value && w.field != "DriverInit") {
            add(w.field, *w.value);
        }
    }
    for (const auto& reg : d.wdfDrivers) {
        for (const auto& cb : reg.callbacks) {
            add(cb.name, cb.function);
        }
    }
    int queueNo = 0;
    for (const auto& q : d.wdfQueues) {
        ++queueNo;
        for (const auto& cb : q.callbacks) {
            add(cb.name + " (queue " + std::to_string(queueNo) + ")", cb.function);
        }
    }
    return roots;
}

// Function RVA -> names of the entry points that reach it via direct or
// tail calls.
std::unordered_map<std::uint64_t, std::set<std::string>> computeReach(const functions::FunctionSet& set,
                                                                      const Roots& roots) {
    std::unordered_map<std::uint64_t, std::set<std::string>> reach;
    for (const auto& [name, root] : roots) {
        std::deque<std::uint64_t> work{root};
        std::set<std::uint64_t> seen{root};
        while (!work.empty()) {
            const std::uint64_t rva = work.front();
            work.pop_front();
            reach[rva].insert(name);
            const Function* fn = set.find(rva);
            if (fn == nullptr) {
                continue;
            }
            for (const auto& call : fn->calls) {
                if (call.target && set.find(*call.target) != nullptr && seen.insert(*call.target).second) {
                    work.push_back(*call.target);
                }
            }
        }
    }
    return reach;
}

// ------------------------------------------- MmGetSystemRoutineAddress ----

class RoutineNameCollector : public driver::TrackerHooks {
public:
    explicit RoutineNameCollector(const pe::PEImage& image) : m_image(image) {}

    bool stringsOnly = true;
    std::uint64_t currentFunction = 0;
    std::map<std::pair<Reg, std::int64_t>, std::string> stackStrings;
    std::map<std::uint64_t, std::string> globalStrings;
    // (name or "" if unresolved, caller, call site)
    std::vector<std::tuple<std::string, std::uint64_t, std::uint64_t>> resolved;

    void onCall(const Instruction& insn, const driver::CallInfo& info, const TrackerState& s) override {
        const std::string_view fn = functionPart(info.importName);
        if (fn == "RtlInitUnicodeString") {
            const Value src = s.reg(Reg::Rdx);
            if (!src.is(Kind::Address)) {
                return;
            }
            auto text = pe::utf16At(m_image, static_cast<std::uint64_t>(src.a), 256);
            if (!text) {
                return;
            }
            const Value dst = s.reg(Reg::Rcx);
            if (dst.is(Kind::Stack)) {
                stackStrings[{dst.base, dst.a}] = *text;
            } else if (dst.is(Kind::Address)) {
                globalStrings[static_cast<std::uint64_t>(dst.a)] = *text;
            }
        } else if (!stringsOnly && fn == "MmGetSystemRoutineAddress") {
            // MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
            const Value arg = s.reg(Reg::Rcx);
            std::string name;
            if (arg.is(Kind::Stack)) {
                if (auto it = stackStrings.find({arg.base, arg.a}); it != stackStrings.end()) {
                    name = it->second;
                }
            } else if (arg.is(Kind::Address)) {
                const auto rva = static_cast<std::uint64_t>(arg.a);
                if (auto it = globalStrings.find(rva); it != globalStrings.end()) {
                    name = it->second;
                } else if (auto text = pe::unicodeStringAt(m_image, rva)) {
                    name = *text;
                }
            }
            resolved.emplace_back(name, currentFunction, insn.rva);
        }
    }

private:
    const pe::PEImage& m_image;
};

// ----------------------------------------------- privileged instructions ----

struct PrivilegedKind {
    const char* kind;
    ApiRisk risk;
};

std::optional<PrivilegedKind> classifyPrivileged(const Instruction& insn) {
    const std::string& m = insn.mnemonic;
    if (m == "wrmsr") return PrivilegedKind{"MSR write", ApiRisk::Critical};
    if (m == "rdmsr") return PrivilegedKind{"MSR read", ApiRisk::High};
    if (m == "out" || m.rfind("outs", 0) == 0) return PrivilegedKind{"Port I/O write", ApiRisk::Critical};
    if (m == "in" || m == "insb" || m == "insw" || m == "insd") return PrivilegedKind{"Port I/O read", ApiRisk::High};
    if (m == "lgdt" || m == "lidt" || m == "lldt" || m == "ltr") {
        return PrivilegedKind{"Descriptor table load", ApiRisk::Critical};
    }
    if (m == "wbinvd" || m == "invd") return PrivilegedKind{"Cache invalidation", ApiRisk::Medium};
    if (m == "xsetbv") return PrivilegedKind{"Extended control register write", ApiRisk::Medium};
    if (m == "mov" && insn.operands.size() >= 2) {
        const std::string& o = insn.operands;
        const bool toCr = o.rfind("cr", 0) == 0;
        const bool fromCr = !toCr && o.find(", cr") != std::string::npos;
        const bool toDr = o.rfind("dr", 0) == 0;
        const bool fromDr = !toDr && o.find(", dr") != std::string::npos;
        if (toCr) return PrivilegedKind{"Control register write", ApiRisk::Critical};
        if (fromCr) return PrivilegedKind{"Control register read", ApiRisk::Medium};
        if (toDr) return PrivilegedKind{"Debug register write", ApiRisk::High};
        if (fromDr) return PrivilegedKind{"Debug register read", ApiRisk::Medium};
    }
    return std::nullopt;
}

} // namespace

KernelApiAnalysis analyzeKernelApis(const pe::PEImage& image, const functions::FunctionSet& set,
                                    const driver::DriverAnalysis& d, const ioctl::IoctlAnalysis&) {
    KernelApiAnalysis out;
    const Roots roots = collectRoots(set, d);
    for (const auto& [name, rva] : roots) {
        out.entryPoints.push_back(name);
    }
    out.entryPointFunctions = roots;
    const auto reach = computeReach(set, roots);
    auto reachOf = [&](std::uint64_t fn) {
        auto it = reach.find(fn);
        return it == reach.end() ? std::set<std::string>{} : it->second;
    };

    // Imports.
    std::unordered_map<std::string, std::size_t> byImportName; // "dll!name" -> index
    for (const auto& lib : image.imports) {
        for (const auto& fn : lib.functions) {
            if (fn.name.empty()) {
                continue;
            }
            ApiUse use;
            use.name = fn.name;
            use.library = lib.name;
            use.info = classifyApi(fn.name);
            use.imported = true;
            byImportName.emplace(lib.name + "!" + fn.name, out.apis.size());
            out.apis.push_back(std::move(use));
        }
    }
    for (const auto& fn : set.functions) {
        for (const auto& call : fn.calls) {
            if (call.importName.empty()) {
                continue;
            }
            auto it = byImportName.find(call.importName);
            if (it == byImportName.end()) {
                continue;
            }
            ApiUse& use = out.apis[it->second];
            if (std::find(use.callers.begin(), use.callers.end(), fn.rva) == use.callers.end()) {
                use.callers.push_back(fn.rva);
            }
            use.callSites.push_back(call.rva);
            const auto r = reachOf(fn.rva);
            use.reachableFrom.insert(r.begin(), r.end());
        }
    }

    // Names resolved at runtime.
    if (image.machine == 0x8664 && byImportName.count("ntoskrnl.exe!MmGetSystemRoutineAddress") != 0) {
        driver::TrackerContext ctx = driver::makeTrackerContext(image, set);
        RoutineNameCollector c(image);
        for (bool stringsOnly : {true, false}) {
            c.stringsOnly = stringsOnly;
            for (const auto& fn : set.functions) {
                TrackerState state;
                c.currentFunction = fn.rva;
                c.stackStrings.clear();
                driver::trackFunction(fn, ctx, state, c);
            }
        }
        int unresolved = 0;
        for (const auto& [name, caller, site] : c.resolved) {
            if (name.empty()) {
                ++unresolved;
                continue;
            }
            auto existing = std::find_if(out.apis.begin(), out.apis.end(),
                                         [&](const ApiUse& u) { return u.resolvedAtRuntime && u.name == name; });
            if (existing == out.apis.end()) {
                ApiUse use;
                use.name = name;
                use.library = "MmGetSystemRoutineAddress";
                use.info = classifyApi(name);
                use.resolvedAtRuntime = true;
                out.apis.push_back(std::move(use));
                existing = std::prev(out.apis.end());
            }
            existing->callers.push_back(caller);
            existing->callSites.push_back(site);
            const auto r = reachOf(caller);
            existing->reachableFrom.insert(r.begin(), r.end());
        }
        if (unresolved > 0) {
            out.notes.push_back(std::to_string(unresolved) +
                                " MmGetSystemRoutineAddress call(s) look up a name that couldn't be "
                                "resolved statically.");
        }
    }

    // Privileged instructions.
    for (const auto& fn : set.functions) {
        for (const auto& insn : fn.instructions) {
            if (auto k = classifyPrivileged(insn)) {
                PrivilegedInstruction p;
                p.rva = insn.rva;
                p.function = fn.rva;
                p.text = insn.text();
                p.kind = k->kind;
                p.risk = k->risk;
                p.reachableFrom = reachOf(fn.rva);
                out.privileged.push_back(std::move(p));
            }
        }
    }

    std::sort(out.apis.begin(), out.apis.end(), [](const ApiUse& a, const ApiUse& b) {
        if (a.info.risk != b.info.risk) {
            return static_cast<int>(a.info.risk) > static_cast<int>(b.info.risk);
        }
        return a.name < b.name;
    });
    for (const auto& a : out.apis) {
        out.categoryCounts[a.info.category]++;
    }
    if (roots.empty()) {
        out.notes.push_back("No entry points were recovered, so reachability couldn't be computed.");
    }
    spdlog::info("Kernel APIs in {}: {} APIs ({} critical/high), {} privileged instructions", image.fileName,
                 out.apis.size(), out.countAtLeast(ApiRisk::High), out.privileged.size());
    return out;
}

} // namespace dasa::core::security
