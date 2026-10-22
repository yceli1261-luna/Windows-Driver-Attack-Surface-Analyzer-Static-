#include "analysis/diff/AnalysisDiff.h"

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

#include "core/ioctl/IoctlCodec.h"

namespace dasa::analysis {

namespace fn = core::functions;
using core::disasm::Operand;
using core::disasm::Reg;

const char* functionChangeName(FunctionChange c) {
    switch (c) {
    case FunctionChange::Identical: return "identical";
    case FunctionChange::Changed: return "changed";
    case FunctionChange::Added: return "added";
    case FunctionChange::Removed: return "removed";
    }
    return "";
}

namespace {

// FNV-1a over the bytes of a string.
std::uint64_t fnv(std::uint64_t h, const std::string& s) {
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

bool isGenericName(const std::string& name) {
    return name.rfind("sub_", 0) == 0 || name == "EntryPoint";
}

std::set<std::string> importCalls(const fn::Function& f) {
    std::set<std::string> s;
    for (const auto& c : f.calls) {
        if (!c.importName.empty()) {
            s.insert(c.importName);
        }
    }
    return s;
}

double jaccard(const std::set<std::string>& a, const std::set<std::string>& b) {
    if (a.empty() && b.empty()) {
        return 1.0;
    }
    std::size_t common = 0;
    for (const auto& x : a) {
        common += b.count(x);
    }
    return static_cast<double>(common) / static_cast<double>(a.size() + b.size() - common);
}

template <typename Set>
NamedDelta delta(const Set& oldSet, const Set& newSet) {
    NamedDelta d;
    for (const auto& x : newSet) {
        if (!oldSet.count(x)) {
            d.added.push_back(x);
        }
    }
    for (const auto& x : oldSet) {
        if (!newSet.count(x)) {
            d.removed.push_back(x);
        }
    }
    return d;
}

std::set<std::string> importSet(const AnalysisResult& r) {
    std::set<std::string> s;
    for (const auto& lib : r.image->imports) {
        for (const auto& f : lib.functions) {
            s.insert(lib.name + "!" + (f.name.empty() ? "#" + std::to_string(f.ordinal.value_or(0)) : f.name));
        }
    }
    return s;
}

std::set<std::string> riskyApiNames(const AnalysisResult& r) {
    std::set<std::string> s;
    for (const auto& a : r.kernelApis->apis) {
        if (a.info.risk >= core::security::ApiRisk::High) {
            s.insert(a.name);
        }
    }
    return s;
}

} // namespace

std::uint64_t functionFingerprint(const fn::Function& f) {
    std::uint64_t h = 1469598103934665603ull;
    for (const auto& i : f.instructions) {
        std::string tok = i.mnemonic;
        for (std::uint8_t k = 0; k < i.opCount; ++k) {
            const Operand& op = i.ops[k];
            switch (op.kind) {
            case Operand::Kind::Register:
                tok += " r" + std::to_string(static_cast<int>(op.reg));
                break;
            case Operand::Kind::Immediate:
                // Branch targets and address immediates move between builds.
                tok += (i.branchTarget || i.immediateRef) ? std::string(" a") : " i" + std::to_string(op.imm);
                break;
            case Operand::Kind::Memory:
                tok += " m" + std::to_string(static_cast<int>(op.base)) + "," + std::to_string(static_cast<int>(op.index)) +
                       "," + std::to_string(op.scale) + "," +
                       (op.base == Reg::Rip || op.base == Reg::None ? std::string("a") : std::to_string(op.disp));
                break;
            default:
                break;
            }
        }
        if (i.operands.find("cr") != std::string::npos || i.operands.find("xmm") != std::string::npos) {
            tok += " " + i.operands; // registers the Reg enum folds into Other
        }
        h = fnv(h, tok + ";");
    }
    return h;
}

AnalysisDiff diffAnalyses(const AnalysisResult& oldR, const AnalysisResult& newR) {
    AnalysisDiff d;
    d.oldFile = oldR.image->fileName;
    d.newFile = newR.image->fileName;
    d.sameFile = oldR.image->hashes.sha256 == newR.image->hashes.sha256;
    d.riskOld = oldR.findings->risk.score;
    d.riskNew = newR.findings->risk.score;

    const auto& oldFns = oldR.functions->functions;
    const auto& newFns = newR.functions->functions;
    std::vector<bool> oldUsed(oldFns.size(), false), newUsed(newFns.size(), false);
    std::vector<std::uint64_t> oldFp(oldFns.size()), newFp(newFns.size());
    for (std::size_t i = 0; i < oldFns.size(); ++i) oldFp[i] = functionFingerprint(oldFns[i]);
    for (std::size_t i = 0; i < newFns.size(); ++i) newFp[i] = functionFingerprint(newFns[i]);

    const auto riskyOld = riskyApiNames(oldR);
    const auto riskyNew = riskyApiNames(newR);
    auto touchesRisky = [&](const fn::Function* o, const fn::Function* n) {
        auto check = [](const fn::Function* f, const std::set<std::string>& risky) {
            if (!f) return false;
            for (const auto& c : f->calls) {
                const auto bang = c.importName.find('!');
                if (bang != std::string::npos && risky.count(c.importName.substr(bang + 1))) return true;
            }
            return false;
        };
        return check(o, riskyOld) || check(n, riskyNew);
    };
    auto record = [&](FunctionChange change, std::size_t oi, std::size_t ni, const char* by) {
        FunctionDiff fd;
        fd.change = change;
        const fn::Function* o = oi < oldFns.size() ? &oldFns[oi] : nullptr;
        const fn::Function* n = ni < newFns.size() ? &newFns[ni] : nullptr;
        if (o) {
            fd.oldRva = o->rva;
            fd.oldName = o->name;
            fd.oldInstructions = o->instructions.size();
            oldUsed[oi] = true;
        }
        if (n) {
            fd.newRva = n->rva;
            fd.newName = n->name;
            fd.newInstructions = n->instructions.size();
            newUsed[ni] = true;
        }
        fd.matchedBy = by;
        if (o && n && change == FunctionChange::Changed) {
            const auto nd = delta(importCalls(*o), importCalls(*n));
            fd.importsAdded = nd.added;
            fd.importsRemoved = nd.removed;
        }
        fd.touchesRiskyApi = touchesRisky(o, n);
        d.functions.push_back(std::move(fd));
    };

    // 1. Unique fingerprints present once on each side.
    std::unordered_map<std::uint64_t, std::vector<std::size_t>> byFpOld, byFpNew;
    for (std::size_t i = 0; i < oldFns.size(); ++i) byFpOld[oldFp[i]].push_back(i);
    for (std::size_t i = 0; i < newFns.size(); ++i) byFpNew[newFp[i]].push_back(i);
    for (std::size_t i = 0; i < oldFns.size(); ++i) {
        const auto& o = byFpOld[oldFp[i]];
        const auto it = byFpNew.find(oldFp[i]);
        if (o.size() == 1 && it != byFpNew.end() && it->second.size() == 1) {
            record(FunctionChange::Identical, i, it->second.front(), "fingerprint");
        }
    }
    // 2. Same non-generic name.
    std::unordered_map<std::string, std::size_t> newByName;
    for (std::size_t i = 0; i < newFns.size(); ++i) {
        if (!newUsed[i] && !isGenericName(newFns[i].name)) newByName.emplace(newFns[i].name, i);
    }
    for (std::size_t i = 0; i < oldFns.size(); ++i) {
        if (oldUsed[i] || isGenericName(oldFns[i].name)) continue;
        const auto it = newByName.find(oldFns[i].name);
        if (it != newByName.end() && !newUsed[it->second]) {
            record(oldFp[i] == newFp[it->second] ? FunctionChange::Identical : FunctionChange::Changed, i, it->second,
                   "name");
        }
    }
    // 3. Remaining duplicates of a fingerprint, paired in address order.
    for (auto& [fp, olds] : byFpOld) {
        const auto it = byFpNew.find(fp);
        if (it == byFpNew.end()) continue;
        std::vector<std::size_t> a, b;
        for (auto i : olds) if (!oldUsed[i]) a.push_back(i);
        for (auto i : it->second) if (!newUsed[i]) b.push_back(i);
        for (std::size_t k = 0; k < a.size() && k < b.size(); ++k) {
            record(FunctionChange::Identical, a[k], b[k], "fingerprint");
        }
    }
    // 4. Similar import calls and size (greedy, best pair first).
    struct Candidate {
        double score;
        std::size_t o, n;
    };
    std::vector<Candidate> candidates;
    std::vector<std::set<std::string>> newCalls(newFns.size());
    for (std::size_t j = 0; j < newFns.size(); ++j) {
        if (!newUsed[j]) newCalls[j] = importCalls(newFns[j]);
    }
    for (std::size_t i = 0; i < oldFns.size(); ++i) {
        if (oldUsed[i] || oldFns[i].instructions.size() < 8) continue;
        const auto oi = importCalls(oldFns[i]);
        for (std::size_t j = 0; j < newFns.size(); ++j) {
            if (newUsed[j] || newFns[j].instructions.size() < 8) continue;
            const double so = static_cast<double>(oldFns[i].instructions.size());
            const double sn = static_cast<double>(newFns[j].instructions.size());
            const double ratio = std::min(so, sn) / std::max(so, sn);
            if (ratio < 0.5) continue;
            const auto& nj = newCalls[j];
            if (oi.empty() || nj.empty()) continue; // nothing distinctive to match on
            const double sim = jaccard(oi, nj);
            if (sim < 0.6) continue;
            candidates.push_back({sim * 0.7 + ratio * 0.3, i, j});
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) { return a.score > b.score; });
    for (const auto& c : candidates) {
        if (!oldUsed[c.o] && !newUsed[c.n]) {
            record(FunctionChange::Changed, c.o, c.n, "similar calls and size");
        }
    }
    // 5. Whatever is left.
    for (std::size_t i = 0; i < oldFns.size(); ++i) {
        if (!oldUsed[i]) record(FunctionChange::Removed, i, newFns.size(), "");
    }
    for (std::size_t j = 0; j < newFns.size(); ++j) {
        if (!newUsed[j]) record(FunctionChange::Added, oldFns.size(), j, "");
    }

    for (const auto& f : d.functions) {
        switch (f.change) {
        case FunctionChange::Identical: ++d.identical; break;
        case FunctionChange::Changed: ++d.changed; break;
        case FunctionChange::Added: ++d.added; break;
        case FunctionChange::Removed: ++d.removed; break;
        }
    }
    auto order = [](FunctionChange c) {
        switch (c) {
        case FunctionChange::Changed: return 0;
        case FunctionChange::Added: return 1;
        case FunctionChange::Removed: return 2;
        case FunctionChange::Identical: break;
        }
        return 3;
    };
    std::stable_sort(d.functions.begin(), d.functions.end(), [&](const FunctionDiff& a, const FunctionDiff& b) {
        if (order(a.change) != order(b.change)) return order(a.change) < order(b.change);
        if (a.touchesRiskyApi != b.touchesRiskyApi) return a.touchesRiskyApi;
        return (a.newRva ? a.newRva : a.oldRva) < (b.newRva ? b.newRva : b.oldRva);
    });

    d.imports = delta(importSet(oldR), importSet(newR));
    {
        std::set<std::string> a, b;
        for (const auto& e : oldR.image->exports) a.insert(e.name);
        for (const auto& e : newR.image->exports) b.insert(e.name);
        d.exports = delta(a, b);
    }
    {
        auto secs = [](const AnalysisResult& r) {
            std::set<std::string> s;
            for (const auto& x : r.image->sections) {
                std::string flags;
                for (const auto& f : x.flags) flags += (flags.empty() ? "" : "|") + f;
                s.insert(x.name + " (" + flags + ")");
            }
            return s;
        };
        d.sections = delta(secs(oldR), secs(newR));
    }
    {
        auto codes = [](const AnalysisResult& r) {
            std::set<std::string> s;
            for (const auto& e : r.ioctls->ioctls) {
                s.insert(core::ioctl::hexCode(e.decoded.code) + " " + core::ioctl::methodName(e.decoded.method) + " " +
                         core::ioctl::accessName(e.decoded.access));
            }
            return s;
        };
        d.ioctls = delta(codes(oldR), codes(newR));
    }
    {
        auto devs = [](const AnalysisResult& r) {
            std::set<std::string> s;
            for (const auto& x : r.devices->devices) if (!x.name.empty()) s.insert(x.name);
            for (const auto& l : r.devices->symbolicLinks) if (!l.link.empty()) s.insert(l.link);
            return s;
        };
        d.devices = delta(devs(oldR), devs(newR));
    }
    {
        auto finds = [](const AnalysisResult& r) {
            std::set<std::string> s;
            for (const auto& f : r.findings->findings) s.insert(f.ruleId + ": " + f.title);
            return s;
        };
        d.findings = delta(finds(oldR), finds(newR));
    }
    return d;
}

} // namespace dasa::analysis
