#include "core/ioctl/IoctlExtractor.h"

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <string_view>

#include <spdlog/spdlog.h>

#include "core/driver/ValueTracker.h"

namespace dasa::core::ioctl {

using disasm::Flow;
using disasm::Instruction;
using disasm::Operand;
using disasm::Reg;
using driver::TrackerState;
using driver::Value;
using functions::Function;
using Kind = Value::Kind;

const char* evidenceName(IoctlEvidence e) {
    switch (e) {
    case IoctlEvidence::TrackedCompare: return "IoControlCode compare";
    case IoctlEvidence::HandlerConstant: return "constant in handler";
    case IoctlEvidence::ImageScan: return "image-wide scan";
    }
    return "?";
}

namespace {

bool isEqualityJump(const Instruction* i) {
    return i != nullptr && (i->mnemonic == "je" || i->mnemonic == "jne");
}

bool isRelationalJump(const Instruction* i) {
    if (i == nullptr || i->flow != Flow::CondJump) {
        return false;
    }
    static const char* const kRel[] = {"ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle"};
    return std::any_of(std::begin(kRel), std::end(kRel), [&](const char* m) { return i->mnemonic == m; });
}

const Instruction* following(const Function& fn, const Instruction& insn, std::size_t ahead) {
    auto it = std::lower_bound(fn.instructions.begin(), fn.instructions.end(), insn.rva,
                               [](const Instruction& a, std::uint64_t r) { return a.rva < r; });
    if (it == fn.instructions.end()) {
        return nullptr;
    }
    const auto idx = static_cast<std::size_t>(it - fn.instructions.begin()) + ahead;
    return idx < fn.instructions.size() ? &fn.instructions[idx] : nullptr;
}

struct Anchor {
    std::string name;
    std::uint64_t function = 0;
    TrackerState entry;
};

class Collector : public driver::TrackerHooks {
public:
    const Function* fn = nullptr;
    const Anchor* anchor = nullptr;
    std::map<std::uint32_t, ExtractedIoctl> tracked;
    std::map<std::uint32_t, ExtractedIoctl> constants;
    std::vector<IoctlSwitchRange> ranges;
    std::vector<std::pair<std::uint64_t, TrackerState>> callees;
    bool strictConstants = false;

    void onCompare(const Instruction& insn, const Instruction* next, const Value& lhs, std::int64_t imm,
                   bool isSub) override {
        const Instruction* second = next ? following(*fn, *next, 1) : nullptr;
        const Instruction* eq = isEqualityJump(next) ? next
                                : (isRelationalJump(next) && isEqualityJump(second)) ? second
                                                                                      : nullptr;
        if (lhs.is(Kind::IoctlCode)) {
            // The register holds IoControlCode + a, so equality with imm
            // (cmp) or reaching zero (sub) means IoControlCode == imm - a.
            const auto code = static_cast<std::uint32_t>(imm - lhs.a);
            if (eq != nullptr) {
                record(tracked, code, insn, eq, IoctlEvidence::TrackedCompare);
            } else if (!isSub && isRelationalJump(next) && hasIndirectJumpSoon(insn)) {
                IoctlSwitchRange r;
                r.at = insn.rva;
                r.inFunction = fn->rva;
                r.low = static_cast<std::uint32_t>(-lhs.a);
                r.high = code;
                r.handler = anchor->name;
                ranges.push_back(r);
            }
            return;
        }
        const auto value = static_cast<std::uint32_t>(imm);
        if (!isSub && (eq != nullptr || isRelationalJump(next)) && looksLikeIoctl(value, strictConstants)) {
            record(constants, value, insn, eq, strictConstants ? IoctlEvidence::ImageScan
                                                               : IoctlEvidence::HandlerConstant);
        }
    }

    void onCall(const Instruction&, const driver::CallInfo& info, const TrackerState& state) override {
        if (!info.target) {
            return;
        }
        // Follow the request into helpers that receive the IRP, its stack
        // location or the code itself, in the same argument register.
        TrackerState calleeState;
        bool passes = false;
        auto relevant = [](const Value& v) {
            return v.is(Kind::Irp) || v.is(Kind::IrpStack) || v.is(Kind::IoctlCode);
        };
        for (Reg r : {Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9}) {
            if (relevant(state.reg(r))) {
                calleeState.reg(r) = state.reg(r);
                passes = true;
            }
        }
        // x64 stack arguments 5..10: [rsp+0x20..] before the call is
        // [rsp+0x28..] at the callee's entry (past the return address).
        for (std::int64_t off = 0x20; off <= 0x48; off += 8) {
            const Value v = state.stackArg(off);
            if (relevant(v)) {
                calleeState.stack[{Reg::Rsp, off + 8}] = v;
                passes = true;
            }
        }
        if (passes) {
            callees.emplace_back(*info.target, std::move(calleeState));
        }
    }

private:
    bool hasIndirectJumpSoon(const Instruction& insn) const {
        for (std::size_t k = 1; k <= 8; ++k) {
            const Instruction* i = following(*fn, insn, k);
            if (i == nullptr) {
                break;
            }
            if (i->flow == Flow::Jump && !i->branchTarget) {
                return true;
            }
        }
        return false;
    }

    void record(std::map<std::uint32_t, ExtractedIoctl>& into, std::uint32_t code, const Instruction& insn,
                const Instruction* eq, IoctlEvidence evidence) {
        if (into.count(code) != 0) {
            return;
        }
        ExtractedIoctl e;
        e.decoded = decodeIoctl(code);
        e.handler = anchor->name;
        e.handlerFunction = anchor->function;
        e.comparedIn = fn->rva;
        e.at = insn.rva;
        e.evidence = evidence;
        if (eq != nullptr) {
            e.caseTarget = eq->mnemonic == "je" ? eq->branchTarget : std::optional(eq->endRva());
        }
        into.emplace(code, std::move(e));
    }
};

std::vector<Anchor> collectAnchors(const pe::PEImage& image,
                                   const driver::DriverAnalysis& d) {
    const bool x64 = image.machine == 0x8664;
    std::vector<Anchor> anchors;
    auto addOrMerge = [&](const std::string& name, std::uint64_t fn, TrackerState state) {
        for (auto& a : anchors) {
            if (a.function == fn) {
                a.name += " / " + name;
                return;
            }
        }
        anchors.push_back(Anchor{name, fn, std::move(state)});
    };

    for (unsigned major : {0x0Eu, 0x0Fu}) {
        const driver::DispatchEntry* e = d.dispatchFor(major);
        if (e == nullptr || !e->handlerIsFunction) {
            continue;
        }
        TrackerState s; // DispatchRoutine(DeviceObject, Irp)
        if (x64) {
            s.reg(Reg::Rdx) = Value::make(Kind::Irp);
        } else {
            s.stack[{Reg::Rsp, 8}] = Value::make(Kind::Irp); // entry-relative
        }
        addOrMerge(driver::irpMajorName(major), e->handler, std::move(s));
    }

    int queueNo = 0;
    for (const auto& q : d.wdfQueues) {
        ++queueNo;
        for (const auto& cb : q.callbacks) {
            const bool ioctlCallback = cb.name == "EvtIoDeviceControl" || cb.name == "EvtIoInternalDeviceControl";
            if (!cb.isFunction || !(ioctlCallback || cb.name == "EvtIoDefault")) {
                continue;
            }
            TrackerState s;
            if (ioctlCallback && x64) {
                // EvtIoDeviceControl(Queue, Request, OutputBufferLength,
                //                    InputBufferLength, IoControlCode): the
                // 5th argument, at [rsp+0x28] on entry.
                s.stack[{Reg::Rsp, 0x28}] = Value::make(Kind::IoctlCode, 0);
            }
            addOrMerge(cb.name + " (queue " + std::to_string(queueNo) + ")", cb.function, std::move(s));
        }
    }
    return anchors;
}

} // namespace

IoctlAnalysis extractIoctls(const pe::PEImage& image, const functions::FunctionSet& set,
                            const driver::DriverAnalysis& d) {
    IoctlAnalysis out;
    if (image.machine != 0x8664 && image.machine != 0x014C) {
        return out;
    }
    driver::TrackerContext ctx = driver::makeTrackerContext(image, set);
    if (d.wdfBind) {
        ctx.wdfTableVariable = d.wdfBind->functionTableVariable;
    }

    std::map<std::uint32_t, ExtractedIoctl> merged;
    auto merge = [&](const ExtractedIoctl& e) {
        auto it = merged.find(e.decoded.code);
        if (it == merged.end() || static_cast<int>(e.evidence) < static_cast<int>(it->second.evidence)) {
            merged[e.decoded.code] = e;
        }
    };

    const std::vector<Anchor> anchors = collectAnchors(image, d);
    for (const Anchor& anchor : anchors) {
        out.anchors.push_back(anchor.name);
        Collector c;
        c.anchor = &anchor;
        std::deque<std::tuple<std::uint64_t, TrackerState, int>> work;
        work.emplace_back(anchor.function, anchor.entry, 0);
        std::set<std::uint64_t> visited;
        while (!work.empty()) {
            auto [rva, state, depth] = std::move(work.front());
            work.pop_front();
            const Function* fn = set.find(rva);
            if (fn == nullptr || !visited.insert(rva).second) {
                continue;
            }
            c.fn = fn;
            c.callees.clear();
            driver::trackFunction(*fn, ctx, state, c);
            if (depth < 3) {
                for (auto& [callee, calleeState] : c.callees) {
                    work.emplace_back(callee, std::move(calleeState), depth + 1);
                }
            }
        }
        for (const auto& [code, e] : c.tracked) {
            merge(e);
        }
        // Constants only stand in when the code itself couldn't be tracked
        // in this handler; otherwise they are buffer sizes and the like.
        if (c.tracked.empty()) {
            for (const auto& [code, e] : c.constants) {
                merge(e);
            }
        }
        out.switchRanges.insert(out.switchRanges.end(), c.ranges.begin(), c.ranges.end());
    }

    const bool dispatchKnown = !d.majorFunctions.empty() || !d.wdfQueues.empty();
    if (anchors.empty() && dispatchKnown) {
        out.notes.push_back("The driver's request handlers were recovered and none of them handles "
                            "IRP_MJ_DEVICE_CONTROL / INTERNAL_DEVICE_CONTROL (or an EvtIo*DeviceControl "
                            "callback), so it accepts no IOCTLs of its own.");
    } else if (anchors.empty()) {
        // No handler to anchor on: scan everything for vendor-type IOCTL
        // constants and keep the device types that recur (v1's noise filter).
        out.notes.push_back("No IOCTL handler was recovered, so IOCTL-shaped constants were collected "
                            "from the whole image (vendor device types only). Treat these as leads.");
        Anchor scan{"(no handler recovered)", 0, {}};
        Collector c;
        c.anchor = &scan;
        c.strictConstants = true;
        for (const auto& fn : set.functions) {
            TrackerState state;
            c.fn = &fn;
            driver::trackFunction(fn, ctx, state, c);
        }
        std::map<std::uint32_t, int> typeCounts;
        for (const auto& [code, e] : c.constants) {
            typeCounts[e.decoded.deviceType]++;
        }
        std::vector<std::pair<int, std::uint32_t>> ranked;
        for (const auto& [t, n] : typeCounts) {
            ranked.emplace_back(n, t);
        }
        std::sort(ranked.rbegin(), ranked.rend());
        std::set<std::uint32_t> keep;
        for (std::size_t i = 0; i < ranked.size() && i < 3; ++i) {
            if (ranked[i].first >= 2) {
                keep.insert(ranked[i].second);
            }
        }
        for (const auto& [code, e] : c.constants) {
            if (keep.count(e.decoded.deviceType) != 0) {
                merge(e);
            }
        }
    } else if (merged.empty() && out.switchRanges.empty()) {
        out.notes.push_back("Handlers were found but no IOCTL comparisons were recovered in them or "
                            "the helpers they pass the request to.");
    }
    for (const auto& r : out.switchRanges) {
        out.notes.push_back("A jump-table switch in " + r.handler + " covers IOCTL codes " + hexCode(r.low) +
                            " to " + hexCode(r.high) + "; its individual cases are not decoded yet.");
    }

    for (auto& [code, e] : merged) {
        out.ioctls.push_back(std::move(e));
    }
    spdlog::info("IOCTLs in {}: {} codes from {} handlers, {} switch ranges", image.fileName, out.ioctls.size(),
                 anchors.size(), out.switchRanges.size());
    return out;
}

} // namespace dasa::core::ioctl
