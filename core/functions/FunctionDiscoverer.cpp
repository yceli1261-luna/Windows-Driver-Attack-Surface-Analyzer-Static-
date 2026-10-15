#include "core/functions/FunctionDiscoverer.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <queue>
#include <set>
#include <unordered_set>

#include <spdlog/spdlog.h>

#include "core/disasm/Disassembler.h"

namespace dasa::core::functions {

namespace {

using disasm::Flow;
using disasm::Instruction;

// Guard against runaway decoding of a single "function" in data or
// pathological code.
constexpr std::size_t kMaxInstructionsPerFunction = 200000;

// Calls that never return; disassembling past them walks into whatever
// follows (often the next function or padding).
bool isNoReturnImport(const std::string& importName) {
    static const char* const kNames[] = {"!KeBugCheck", "!KeBugCheckEx", "!ExRaiseStatus",
                                         "!RtlRaiseStatus", "!ExRaiseAccessViolation",
                                         "!ExRaiseDatatypeMisalignment", "!RtlFailFast"};
    for (const char* n : kNames) {
        const std::string suffix(n);
        if (importName.size() >= suffix.size() &&
            importName.compare(importName.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
    }
    return false;
}

// Lower rank = processed first. High-confidence starts are disassembled
// before speculative ones so the latter can be checked against code that
// is already known to belong to a function.
int rankOf(std::uint32_t source) {
    if (source & (kEntryPoint | kExport | kExceptionTable)) {
        return 0;
    }
    if (source & kCallTarget) {
        return 1;
    }
    return 2; // address-taken, tail calls
}

struct Seed {
    std::uint64_t rva;
    std::uint32_t source;
    std::uint64_t order; // FIFO within a rank
    bool operator>(const Seed& o) const {
        const int a = rankOf(source), b = rankOf(o.source);
        return a != b ? a > b : order > o.order;
    }
};

std::string hexName(const char* prefix, std::uint64_t rva) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%s%llX", prefix, static_cast<unsigned long long>(rva));
    return buf;
}

class Discoverer {
public:
    explicit Discoverer(const pe::PEImage& image)
        : m_image(image),
          m_disasm(image.machine == 0x8664 ? disasm::Arch::X64 : disasm::Arch::X86, image.imageBase,
                   image.sizeOfImage),
          m_imports(buildImportMap(image)) {
        for (const auto& rf : image.runtimeFunctions) {
            m_ranges[rf.primaryBegin].emplace_back(rf.begin, rf.end);
        }
        for (auto& [begin, ranges] : m_ranges) {
            m_knownStarts.insert(begin);
            const auto primary = std::find_if(ranges.begin(), ranges.end(),
                                              [b = begin](const auto& r) { return r.first == b; });
            if (primary != ranges.end()) {
                m_declaredEnd[begin] = primary->second;
            }
        }
        if (image.entryPointRva != 0) {
            m_knownStarts.insert(image.entryPointRva);
        }
        for (const auto& e : image.exports) {
            if (e.forwarder.empty() && e.rva != 0) {
                m_knownStarts.insert(e.rva);
            }
        }
    }

    FunctionSet run() {
        if (m_image.entryPointRva != 0) {
            enqueue(m_image.entryPointRva, kEntryPoint);
        }
        for (const auto& e : m_image.exports) {
            if (e.forwarder.empty() && e.rva != 0) {
                enqueue(e.rva, kExport);
            }
        }
        for (const auto& [begin, ranges] : m_ranges) {
            enqueue(begin, kExceptionTable);
        }

        while (!m_queue.empty()) {
            const Seed seed = m_queue.top();
            m_queue.pop();
            process(seed);
        }

        FunctionSet set;
        set.functions.reserve(m_functions.size());
        for (auto& [rva, fn] : m_functions) {
            set.functions.push_back(std::move(fn));
        }
        set.rejectedSeeds.assign(m_rejected.begin(), m_rejected.end());
        linkCallers(set);
        nameFunctions(set);
        return set;
    }

private:
    void enqueue(std::uint64_t rva, std::uint32_t source) {
        m_queue.push(Seed{rva, source, m_order++});
    }

    bool isOtherKnownStart(std::uint64_t rva, std::uint64_t self) const {
        return rva != self && (m_knownStarts.count(rva) != 0 || m_functions.count(rva) != 0);
    }

    void process(const Seed& seed) {
        if (auto it = m_functions.find(seed.rva); it != m_functions.end()) {
            it->second.sources |= seed.source;
            return;
        }
        if (m_rejected.count(seed.rva) != 0) {
            return;
        }
        if (!m_image.isExecutable(seed.rva)) {
            m_rejected.insert(seed.rva);
            return;
        }
        const auto first = m_disasm.decode(m_image.bytesAt(seed.rva), seed.rva);
        if (!first || first->flow == Flow::Trap) {
            m_rejected.insert(seed.rva);
            return;
        }
        // Speculative seeds that land inside code already attributed to a
        // function are interior labels (jump tables, SEH targets), not
        // function starts.
        if (rankOf(seed.source) == 2 && m_ownedCode.count(seed.rva) != 0) {
            m_rejected.insert(seed.rva);
            return;
        }

        Function fn;
        fn.rva = seed.rva;
        fn.sources = seed.source;
        if (auto it = m_declaredEnd.find(seed.rva); it != m_declaredEnd.end()) {
            fn.declaredEnd = it->second;
        }
        disassemble(fn);
        for (const auto& insn : fn.instructions) {
            m_ownedCode.insert(insn.rva);
        }
        m_knownStarts.insert(fn.rva);
        m_functions.emplace(fn.rva, std::move(fn));
    }

    bool inDeclaredRange(std::uint64_t entry, std::uint64_t target) const {
        const auto it = m_ranges.find(entry);
        if (it == m_ranges.end()) {
            return true; // no .pdata for this function: no range to enforce
        }
        return std::any_of(it->second.begin(), it->second.end(), [target](const auto& r) {
            return target >= r.first && target < r.second;
        });
    }

    void noteReferences(const Instruction& insn) {
        if (insn.memoryRef && insn.memoryRefIsAddressOf && m_image.isExecutable(*insn.memoryRef)) {
            enqueue(*insn.memoryRef, kAddressTaken);
        }
        if (insn.immediateRef && m_image.isExecutable(*insn.immediateRef)) {
            enqueue(*insn.immediateRef, kAddressTaken);
        }
    }

    void disassemble(Function& fn) {
        std::map<std::uint64_t, Instruction> code;
        std::set<std::uint64_t> leaders{fn.rva};
        std::vector<std::uint64_t> work{fn.rva};

        while (!work.empty()) {
            std::uint64_t cur = work.back();
            work.pop_back();
            while (true) {
                if (code.count(cur) != 0) {
                    leaders.insert(cur);
                    break;
                }
                if (isOtherKnownStart(cur, fn.rva) || !m_image.isExecutable(cur) ||
                    !inDeclaredRange(fn.rva, cur)) {
                    // Fell through into another function or out of code.
                    break;
                }
                if (code.size() >= kMaxInstructionsPerFunction) {
                    fn.truncated = true;
                    break;
                }
                auto decoded = m_disasm.decode(m_image.bytesAt(cur), cur);
                if (!decoded) {
                    fn.truncated = true;
                    break;
                }
                const Instruction& insn = code.emplace(cur, std::move(*decoded)).first->second;
                noteReferences(insn);

                bool stop = false;
                switch (insn.flow) {
                case Flow::Normal:
                    break;
                case Flow::Call: {
                    CallSite call;
                    call.rva = insn.rva;
                    if (insn.branchTarget) {
                        call.target = insn.branchTarget;
                        enqueue(*insn.branchTarget, kCallTarget);
                    } else if (insn.memoryRef) {
                        if (auto imp = m_imports.find(*insn.memoryRef); imp != m_imports.end()) {
                            call.importName = imp->second;
                        }
                    }
                    stop = isNoReturnImport(call.importName);
                    fn.calls.push_back(std::move(call));
                    break;
                }
                case Flow::CondJump:
                    if (insn.branchTarget) {
                        const std::uint64_t t = *insn.branchTarget;
                        if (!isOtherKnownStart(t, fn.rva) && inDeclaredRange(fn.rva, t)) {
                            leaders.insert(t);
                            work.push_back(t);
                        } else {
                            fn.calls.push_back(CallSite{insn.rva, t, {}, true});
                            enqueue(t, kTailCall);
                        }
                    }
                    leaders.insert(insn.endRva());
                    break;
                case Flow::Jump:
                    if (insn.branchTarget) {
                        const std::uint64_t t = *insn.branchTarget;
                        if (!isOtherKnownStart(t, fn.rva) && inDeclaredRange(fn.rva, t)) {
                            leaders.insert(t);
                            work.push_back(t);
                        } else {
                            fn.calls.push_back(CallSite{insn.rva, t, {}, true});
                            enqueue(t, kTailCall);
                        }
                    } else if (insn.memoryRef && m_imports.count(*insn.memoryRef) != 0) {
                        CallSite call{insn.rva, std::nullopt, m_imports.at(*insn.memoryRef), true};
                        fn.calls.push_back(std::move(call));
                    } else {
                        fn.hasUnresolvedIndirectJump = true;
                    }
                    stop = true;
                    break;
                case Flow::Return:
                case Flow::Trap:
                    stop = true;
                    break;
                }
                if (stop) {
                    break;
                }
                cur = insn.endRva();
            }
        }

        fn.instructions.reserve(code.size());
        for (auto& [rva, insn] : code) {
            fn.instructions.push_back(std::move(insn));
        }
        buildBlocks(fn, leaders);
    }

    static void buildBlocks(Function& fn, const std::set<std::uint64_t>& leaders) {
        const auto& ins = fn.instructions;
        if (ins.empty()) {
            return;
        }
        auto has = [&](std::uint64_t rva) {
            const auto it = std::lower_bound(ins.begin(), ins.end(), rva,
                                             [](const Instruction& a, std::uint64_t r) { return a.rva < r; });
            return it != ins.end() && it->rva == rva;
        };

        BasicBlock block;
        auto close = [&](std::size_t lastIndex) {
            const Instruction& last = ins[lastIndex];
            block.end = last.endRva();
            switch (last.flow) {
            case Flow::CondJump:
                if (last.branchTarget && has(*last.branchTarget)) {
                    block.successors.push_back(*last.branchTarget);
                }
                if (has(last.endRva())) {
                    block.successors.push_back(last.endRva());
                }
                break;
            case Flow::Jump:
                if (last.branchTarget && has(*last.branchTarget)) {
                    block.successors.push_back(*last.branchTarget);
                }
                break;
            case Flow::Normal:
            case Flow::Call:
                if (has(last.endRva())) {
                    block.successors.push_back(last.endRva());
                }
                break;
            case Flow::Return:
            case Flow::Trap:
                break;
            }
            fn.blocks.push_back(std::move(block));
            block = BasicBlock{};
        };

        for (std::size_t i = 0; i < ins.size(); ++i) {
            const Instruction& insn = ins[i];
            if (i == 0) {
                block.start = insn.rva;
                block.firstInstruction = 0;
            } else {
                const Instruction& prev = ins[i - 1];
                const bool prevEnds = prev.flow == Flow::Jump || prev.flow == Flow::CondJump ||
                                      prev.flow == Flow::Return || prev.flow == Flow::Trap;
                const bool gap = prev.endRva() != insn.rva;
                if (prevEnds || gap || leaders.count(insn.rva) != 0) {
                    close(i - 1);
                    block.start = insn.rva;
                    block.firstInstruction = static_cast<std::uint32_t>(i);
                }
            }
            ++block.instructionCount;
            fn.codeBytes += insn.size;
        }
        close(ins.size() - 1);

        fn.lowRva = ins.front().rva;
        fn.highRva = ins.back().endRva();
    }

    void linkCallers(FunctionSet& set) const {
        for (const auto& caller : set.functions) {
            for (const auto& call : caller.calls) {
                if (!call.target) {
                    continue;
                }
                auto it = std::lower_bound(set.functions.begin(), set.functions.end(), *call.target,
                                           [](const Function& f, std::uint64_t r) { return f.rva < r; });
                if (it != set.functions.end() && it->rva == *call.target &&
                    std::find(it->callers.begin(), it->callers.end(), caller.rva) == it->callers.end()) {
                    it->callers.push_back(caller.rva);
                }
            }
        }
    }

    void nameFunctions(FunctionSet& set) const {
        std::unordered_map<std::uint64_t, std::string> exportNames;
        for (const auto& e : m_image.exports) {
            if (!e.name.empty() && e.forwarder.empty()) {
                exportNames.emplace(e.rva, e.name);
            }
        }
        for (auto& fn : set.functions) {
            if (auto it = exportNames.find(fn.rva); it != exportNames.end()) {
                fn.name = it->second;
            } else if (fn.rva == m_image.entryPointRva) {
                fn.name = "EntryPoint";
            } else {
                fn.name = hexName("sub_", fn.rva);
            }
        }
    }

    const pe::PEImage& m_image;
    disasm::Disassembler m_disasm;
    std::unordered_map<std::uint64_t, std::string> m_imports;

    std::map<std::uint64_t, std::vector<std::pair<std::uint64_t, std::uint64_t>>> m_ranges;
    std::unordered_map<std::uint64_t, std::uint64_t> m_declaredEnd;
    std::unordered_set<std::uint64_t> m_knownStarts;
    std::unordered_set<std::uint64_t> m_ownedCode;
    std::set<std::uint64_t> m_rejected;
    std::map<std::uint64_t, Function> m_functions;
    std::priority_queue<Seed, std::vector<Seed>, std::greater<>> m_queue;
    std::uint64_t m_order = 0;
};

} // namespace

std::string describeSources(std::uint32_t sources) {
    static const std::pair<std::uint32_t, const char*> kNames[] = {
        {kEntryPoint, "entry point"}, {kExport, "export"},          {kExceptionTable, ".pdata"},
        {kCallTarget, "call target"}, {kAddressTaken, "address taken"}, {kTailCall, "tail call"},
    };
    std::string out;
    for (const auto& [bit, name] : kNames) {
        if (sources & bit) {
            if (!out.empty()) {
                out += ", ";
            }
            out += name;
        }
    }
    return out;
}

const Function* FunctionSet::find(std::uint64_t rva) const {
    auto it = std::lower_bound(functions.begin(), functions.end(), rva,
                               [](const Function& f, std::uint64_t r) { return f.rva < r; });
    return (it != functions.end() && it->rva == rva) ? &*it : nullptr;
}

std::size_t FunctionSet::totalInstructions() const {
    std::size_t n = 0;
    for (const auto& f : functions) {
        n += f.instructions.size();
    }
    return n;
}

std::unordered_map<std::uint64_t, std::string> buildImportMap(const pe::PEImage& image) {
    std::unordered_map<std::uint64_t, std::string> map;
    for (const auto& lib : image.imports) {
        for (const auto& fn : lib.functions) {
            const std::string name =
                fn.name.empty() ? "#" + std::to_string(fn.ordinal.value_or(0)) : fn.name;
            map.emplace(fn.iatRva, lib.name + "!" + name);
        }
    }
    return map;
}

FunctionSet discoverFunctions(const pe::PEImage& image) {
    if (image.machine != 0x8664 && image.machine != 0x014C) {
        spdlog::warn("Function discovery supports x86/x64 only; {} skipped", image.machineName);
        return {};
    }
    if (!image.mappedImage) {
        return {};
    }
    FunctionSet set = Discoverer(image).run();
    spdlog::info("Discovered {} functions ({} instructions) in {}; {} seeds rejected",
                 set.functions.size(), set.totalInstructions(), image.fileName,
                 set.rejectedSeeds.size());
    return set;
}

} // namespace dasa::core::functions
