#include "core/dataflow/TaintAnalyzer.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <deque>
#include <map>
#include <set>
#include <string_view>
#include <unordered_map>

#include "core/disasm/Instruction.h"

namespace dasa::core::dataflow {

using disasm::Flow;
using disasm::Instruction;
using disasm::Operand;
using disasm::Reg;

std::string describeLabels(std::uint32_t labels) {
    std::string out;
    auto add = [&](std::uint32_t bit, const char* text) {
        if (labels & bit) {
            out += (out.empty() ? "" : ", ") + std::string(text);
        }
    };
    add(kUserData, "request data");
    add(kUserLength, "request length");
    add(kUserPointer, "user-mode pointer");
    add(kUserBuffer, "pointer to request data");
    return out;
}

const char* severityName(Severity s) {
    switch (s) {
    case Severity::Critical: return "Critical";
    case Severity::High: return "High";
    case Severity::Medium: break;
    }
    return "Medium";
}

const char* sinkKindName(SinkKind k) {
    switch (k) {
    case SinkKind::ApiArgument: return "API argument";
    case SinkKind::Instruction: return "instruction";
    case SinkKind::MemoryWrite: return "memory write";
    case SinkKind::MemoryRead: return "memory read";
    }
    return "";
}

bool CheckedCall::anyUserControlled() const {
    return std::any_of(args.begin(), args.end(), [](const Arg& a) { return a.kind == Arg::Kind::UserControlled; });
}

namespace {

std::string hex(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

// ------------------------------------------------------------- sinks ----

// Which labels make an argument dangerous.
constexpr std::uint32_t kAddressMask = kUserData | kUserPointer;            // an address the caller picked
constexpr std::uint32_t kScalarMask = kUserData | kUserLength | kUserPointer; // any caller-chosen number
constexpr std::uint32_t kAnyMask = kScalarMask | kUserBuffer;                // even request data by reference

struct SinkArg {
    int index;
    const char* name;
    std::uint32_t mask;
    Severity severity;
    const char* impact;
};

struct ApiSink {
    std::vector<const char*> names;
    std::vector<SinkArg> args;
};

const std::vector<ApiSink>& apiSinks() {
    static const std::vector<ApiSink> sinks = {
        {{"MmMapIoSpace", "MmMapIoSpaceEx"},
         {{0, "PhysicalAddress", kScalarMask, Severity::Critical, "maps physical memory at an address the caller chooses"},
          {1, "NumberOfBytes", kScalarMask, Severity::High, "maps as many bytes as the caller asks for"}}},
        {{"MmCopyMemory"},
         {{0, "TargetAddress", kAddressMask, Severity::Critical, "copies into an address the caller chooses"},
          {1, "SourceAddress", kScalarMask, Severity::Critical, "copies from a physical or virtual address the caller chooses"},
          {2, "NumberOfBytes", kScalarMask, Severity::High, "copy length chosen by the caller"}}},
        {{"memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory", "RtlCopyBytes"},
         {{0, "Destination", kAddressMask, Severity::Critical, "writes to an address the caller chooses"},
          {1, "Source", kAddressMask, Severity::High, "reads from an address the caller chooses"},
          {2, "Length", kUserData | kUserLength, Severity::High,
           "copy length chosen by the caller - overflows the destination unless checked against its size"}}},
        {{"memset", "RtlFillMemory"},
         {{0, "Destination", kAddressMask, Severity::Critical, "writes to an address the caller chooses"},
          {2, "Length", kUserData | kUserLength, Severity::High, "fill length chosen by the caller"}}},
        {{"ExAllocatePool", "ExAllocatePoolWithTag", "ExAllocatePoolWithQuotaTag", "ExAllocatePool2",
          "ExAllocatePoolZero", "ExAllocatePoolUninitialized"},
         {{1, "NumberOfBytes", kUserData | kUserLength, Severity::Medium,
           "allocation size chosen by the caller - check for integer overflow and exhaustion"}}},
        {{"ExFreePool", "ExFreePoolWithTag"},
         {{0, "P", kAddressMask, Severity::Critical, "frees an address the caller chooses"}}},
        {{"MmUnmapIoSpace"},
         {{0, "BaseAddress", kAddressMask, Severity::High, "unmaps an address the caller chooses"}}},
        {{"PsLookupProcessByProcessId", "PsLookupThreadByThreadId"},
         {{0, "Id", kScalarMask, Severity::High, "operates on a process or thread the caller chooses"}}},
        {{"ZwTerminateProcess", "NtTerminateProcess"},
         {{0, "ProcessHandle", kScalarMask, Severity::High, "terminates a process the caller chooses"}}},
        {{"ZwOpenProcess", "NtOpenProcess"},
         {{3, "ClientId", kAnyMask, Severity::High, "opens a process the caller chooses"}}},
        {{"ObReferenceObjectByHandle", "ObReferenceObjectByHandleWithTag"},
         {{0, "Handle", kScalarMask, Severity::Medium,
           "references an object through a caller-supplied handle - check that AccessMode is UserMode"}}},
        {{"MmGetSystemRoutineAddress"},
         {{0, "SystemRoutineName", kAnyMask, Severity::High, "resolves a kernel routine the caller names"}}},
        {{"ZwLoadDriver", "NtLoadDriver"},
         {{0, "DriverServiceName", kAnyMask, Severity::Critical, "loads a driver the caller names"}}},
        {{"IoAllocateMdl"},
         {{0, "VirtualAddress", kUserData, Severity::High, "builds an MDL over an address read from the request"},
          {1, "Length", kUserData | kUserLength, Severity::Medium, "MDL length chosen by the caller"}}},
        {{"KeStackAttachProcess"},
         {{0, "Process", kScalarMask, Severity::High, "attaches to a process the caller chooses"}}},
        {{"ZwCreateFile", "ZwOpenFile", "NtCreateFile", "NtOpenFile"},
         {{2, "ObjectAttributes", kAnyMask, Severity::Medium, "opens a file the caller names"}}},
        {{"ZwDeleteFile"},
         {{0, "ObjectAttributes", kAnyMask, Severity::High, "deletes a file the caller names"}}},
    };
    return sinks;
}

const ApiSink* findSink(std::string_view name) {
    for (const auto& s : apiSinks()) {
        for (const char* n : s.names) {
            if (name == n) {
                return &s;
            }
        }
    }
    return nullptr;
}

// ------------------------------------------------------------ values ----

struct TVal {
    enum class Kind : std::uint8_t { Unknown, Constant, Stack, Irp, IrpStack, Data, ProbeLimitPtr, ProbeLimit };
    Kind kind = Kind::Unknown;
    std::int64_t a = 0;   // Constant value / Stack offset
    Reg base = Reg::None; // Stack base
    std::uint32_t labels = 0;
    int origin = -1;      // first source, index into Engine::m_origins
    // The source of the kUserPointer part, kept separately so a probe of
    // that pointer still counts after it is merged with another buffer
    // (drivers pick SystemBuffer or Type3InputBuffer by transfer method).
    int pointerOrigin = -1;
    // Read from request memory and not combined with anything but
    // constants since: such a value used as an address means the request
    // chose the address. (Sums, indexes and lengths don't qualify - those
    // are usually bounds-checked in ways this analysis doesn't see.)
    bool loaded = false;

    bool operator==(const TVal&) const = default;

    static TVal constant(std::int64_t v) {
        TVal t;
        t.kind = Kind::Constant;
        t.a = v;
        return t;
    }
    static TVal stack(Reg base, std::int64_t off) {
        TVal t;
        t.kind = Kind::Stack;
        t.base = base;
        t.a = off;
        return t;
    }
    static TVal userPointer(int origin) {
        TVal t = data(kUserPointer, origin);
        t.pointerOrigin = origin;
        return t;
    }
    static TVal data(std::uint32_t labels, int origin) {
        TVal t;
        t.kind = labels ? Kind::Data : Kind::Unknown;
        t.labels = labels;
        t.origin = origin;
        return t;
    }
    bool is(Kind k) const { return kind == k; }
    bool tainted() const { return labels != 0; }
};

TVal merge(const TVal& a, const TVal& b) {
    TVal r = TVal::data(a.labels | b.labels, a.origin >= 0 ? a.origin : b.origin);
    r.pointerOrigin = a.pointerOrigin >= 0 ? a.pointerOrigin : b.pointerOrigin;
    return r;
}

bool isClean(const TVal& v) {
    return v.is(TVal::Kind::Unknown) && !v.tainted();
}

// Join at a control-flow merge. A value known on one path and unknown on
// the other keeps what is known (may-taint); two different values combine
// their labels, and stay "loaded" only if both were.
TVal join(const TVal& x, const TVal& y) {
    if (x == y || isClean(y)) {
        return x;
    }
    if (isClean(x)) {
        return y;
    }
    TVal r = TVal::data(x.labels | y.labels, x.origin >= 0 ? x.origin : y.origin);
    r.pointerOrigin = x.pointerOrigin >= 0 ? x.pointerOrigin : y.pointerOrigin;
    r.loaded = x.loaded && y.loaded && r.tainted();
    return r;
}

struct State {
    std::array<TVal, 19> regs{};
    std::map<std::pair<Reg, std::int64_t>, TVal> stack;
    std::int64_t rspDelta = 0;

    TVal& reg(Reg r) { return regs[static_cast<std::size_t>(r)]; }
    const TVal& reg(Reg r) const { return regs[static_cast<std::size_t>(r)]; }
    TVal slot(Reg base, std::int64_t off) const {
        auto it = stack.find({base, off});
        return it == stack.end() ? TVal{} : it->second;
    }
    TVal stackArg(std::int64_t off) const { return slot(Reg::Rsp, off - rspDelta); }

    bool operator==(const State&) const = default;

    // Joins `other` into this state; returns whether anything changed.
    bool joinFrom(const State& other) {
        bool changed = false;
        for (std::size_t i = 0; i < regs.size(); ++i) {
            const TVal j = join(regs[i], other.regs[i]);
            if (!(j == regs[i])) {
                regs[i] = j;
                changed = true;
            }
        }
        for (const auto& [key, v] : other.stack) {
            auto it = stack.find(key);
            const TVal mine = it == stack.end() ? TVal{} : it->second;
            const TVal j = join(mine, v);
            if (it == stack.end() || !(j == mine)) {
                stack[key] = j;
                changed = changed || !(j == mine) || it == stack.end();
            }
        }
        return changed;
    }
};

constexpr std::array<Reg, 4> kArgRegs{Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9};

enum class EntryKind { DeviceControl, InternalDeviceControl, Write, KmdfDeviceControl, KmdfWrite };

struct Entry {
    std::string role;
    std::uint64_t function = 0;
    EntryKind kind = EntryKind::DeviceControl;
};

struct Origin {
    std::string text;
    std::uint64_t at = 0;
};

// --------------------------------------------------------------- engine --

class Engine {
public:
    Engine(const pe::PEImage& image, const functions::FunctionSet& functions, const driver::DriverAnalysis& driver,
           const ioctl::IoctlAnalysis& ioctls, DataFlowAnalysis& out)
        : m_functions(functions), m_ioctls(ioctls), m_out(out) {
        m_imports = functions::buildImportMap(image);
        for (const auto& c : driver.wdfCalls) {
            m_wdfCalls[c.rva] = c.name;
        }
        for (const auto& [slot, name] : m_imports) {
            if (name.size() >= 19 && name.compare(name.size() - 19, 19, "!MmUserProbeAddress") == 0) {
                m_probeLimitSlots.insert(slot);
            }
        }
    }

    void run(const Entry& entry) {
        const auto* fn = m_functions.find(entry.function);
        if (!fn) {
            return;
        }
        m_entry = &entry;
        m_probed.clear();
        m_memo.clear();
        m_walks = 0;
        m_steps = 0;
        m_path.clear();
        m_callSites.clear();

        State s;
        switch (entry.kind) {
        case EntryKind::DeviceControl:
        case EntryKind::InternalDeviceControl:
        case EntryKind::Write:
            s.reg(Reg::Rdx).kind = TVal::Kind::Irp;
            break;
        case EntryKind::KmdfDeviceControl:
            s.reg(Reg::R8) = TVal::data(kUserLength, origin("OutputBufferLength (" + entry.role + " argument)", entry.function));
            s.reg(Reg::R9) = TVal::data(kUserLength, origin("InputBufferLength (" + entry.role + " argument)", entry.function));
            break;
        case EntryKind::KmdfWrite:
            s.reg(Reg::R8) = TVal::data(kUserLength, origin("Length (" + entry.role + " argument)", entry.function));
            break;
        }
        m_requestorModeRead = false;
        const std::size_t firstFlow = m_out.flows.size();
        walkFunction(*fn, s, 0);
        if (m_requestorModeRead) {
            for (std::size_t i = firstFlow; i < m_out.flows.size(); ++i) {
                m_out.flows[i].requestorModeChecked = true;
            }
        }
        if (m_steps > kMaxStepsPerEntry || m_walks > kMaxWalksPerEntry) {
            m_out.notes.push_back("Stopped early in " + entry.role + " (work limit reached): flows deeper in its "
                                  "call tree may be missing.");
        }
    }

    std::size_t walks() const { return m_totalWalks; }

private:
    static constexpr int kMaxDepth = 6;
    static constexpr std::size_t kMaxWalksPerEntry = 4000;
    // Instructions interpreted per handler, fixpoint iterations included.
    static constexpr std::size_t kMaxStepsPerEntry = 1'500'000;

    // The same source at the same instruction always gets the same id, so
    // values compare equal across fixpoint iterations and a ProbeForRead
    // seen in one pass applies in the next.
    int origin(std::string text, std::uint64_t at) {
        const auto key = std::make_pair(text, at);
        if (auto it = m_originIds.find(key); it != m_originIds.end()) {
            return it->second;
        }
        m_origins.push_back({std::move(text), at});
        const int id = static_cast<int>(m_origins.size()) - 1;
        m_originIds.emplace(key, id);
        return id;
    }
    const Origin* originOf(const TVal& v) const {
        return v.origin >= 0 ? &m_origins[static_cast<std::size_t>(v.origin)] : nullptr;
    }
    bool probed(const TVal& v) const {
        const int o = v.pointerOrigin >= 0 ? v.pointerOrigin : v.origin;
        return o >= 0 && m_probed.count(o) != 0;
    }

    void markProbed(const TVal& v) {
        for (int o : {v.origin, v.pointerOrigin}) {
            if (o >= 0) {
                m_probed.insert(o);
            }
        }
    }

    // Buffers of internal device control come from kernel-mode senders:
    // pointers to request data, not user-mode addresses.
    TVal userPointerSource(const char* text, std::uint64_t at) {
        if (m_entry->kind == EntryKind::InternalDeviceControl) {
            return TVal::data(kUserBuffer, origin(text, at));
        }
        return TVal::userPointer(origin(text, at));
    }

    // A key for "this function analysed with these argument kinds".
    static std::string signature(std::uint64_t fn, const State& s) {
        std::string key = std::to_string(fn);
        auto add = [&](const TVal& v) {
            key += ':' + std::to_string(static_cast<int>(v.kind)) + '/' + std::to_string(v.labels);
        };
        for (Reg r : kArgRegs) {
            add(s.reg(r));
        }
        for (int k = 0; k < 4; ++k) {
            add(s.slot(Reg::Rsp, 0x28 + 8 * k));
        }
        return key;
    }

    // Analyses a function from its entry state `s` over its control-flow
    // graph: states are propagated along block edges and joined where paths
    // meet until nothing changes, then one more pass over every block
    // reports sinks from the settled states. Returns what rax can hold at the
    // function's returns.
    TVal walkFunction(const functions::Function& fn, State s, int depth) {
        const std::string key = signature(fn.rva, s) + (m_reporting ? "R" : "D");
        if (auto it = m_memo.find(key); it != m_memo.end()) {
            return it->second;
        }
        if (++m_walks > kMaxWalksPerEntry || m_steps > kMaxStepsPerEntry) {
            return {};
        }
        ++m_totalWalks;
        m_memo[key] = TVal{}; // cuts recursion
        m_path.push_back(fn.rva);

        const auto& blocks = fn.blocks;
        std::unordered_map<std::uint64_t, std::size_t> index;
        for (std::size_t i = 0; i < blocks.size(); ++i) {
            index[blocks[i].start] = i;
        }
        auto runBlock = [&](std::size_t b, State st, TVal* ret) {
            const auto& blk = blocks[b];
            for (std::uint32_t k = 0; k < blk.instructionCount; ++k) {
                const auto& insn = fn.instructions[blk.firstInstruction + k];
                if (++m_steps > kMaxStepsPerEntry) {
                    break;
                }
                if (insn.flow == Flow::Return) {
                    if (ret && st.reg(Reg::Rax).tainted()) {
                        *ret = merge(*ret, st.reg(Reg::Rax));
                    }
                    continue;
                }
                step(fn, insn, st, depth);
            }
            return st;
        };

        TVal ret;
        if (!blocks.empty()) {
            const bool reporting = m_reporting;
            m_reporting = false;
            std::vector<std::optional<State>> in(blocks.size());
            std::deque<std::size_t> work;
            std::vector<bool> queued(blocks.size(), false);
            auto push = [&](std::size_t b) {
                if (!queued[b]) {
                    queued[b] = true;
                    work.push_back(b);
                }
            };
            const auto entryIt = index.find(fn.rva);
            const std::size_t entry = entryIt == index.end() ? 0 : entryIt->second;
            in[entry] = s;
            push(entry);
            std::size_t budget = blocks.size() * 16 + 64;
            auto settle = [&] {
                while (!work.empty() && budget-- > 0) {
                    const std::size_t b = work.front();
                    work.pop_front();
                    queued[b] = false;
                    const State out = runBlock(b, *in[b], nullptr);
                    for (std::uint64_t succ : blocks[b].successors) {
                        const auto it = index.find(succ);
                        if (it == index.end()) {
                            continue;
                        }
                        auto& target = in[it->second];
                        if (!target) {
                            target = out;
                            push(it->second);
                        } else if (target->joinFrom(out)) {
                            push(it->second);
                        }
                    }
                }
            };
            settle();
            // Blocks no edge reaches (handlers entered through an
            // unresolved jump, exception code): start them from the block
            // laid out before them, as a straight-line reading would.
            for (std::size_t b = 0; b < blocks.size(); ++b) {
                if (!in[b]) {
                    in[b] = b > 0 && in[b - 1] ? runBlock(b - 1, *in[b - 1], nullptr) : s;
                    push(b);
                    settle();
                }
            }
            m_reporting = reporting;
            for (std::size_t b = 0; b < blocks.size(); ++b) {
                runBlock(b, *in[b], &ret);
            }
        }
        m_path.pop_back();
        m_memo[key] = ret;
        return ret;
    }

    // ----------------------------------------------------- operands ----

    std::optional<std::pair<Reg, std::int64_t>> slotFor(const State& s, const Operand& op) const {
        if (op.kind != Operand::Kind::Memory || op.index != Reg::None) {
            return std::nullopt;
        }
        if (op.base == Reg::Rsp) {
            return std::pair{Reg::Rsp, op.disp - s.rspDelta};
        }
        if (op.base == Reg::None || op.base == Reg::Rip || op.base == Reg::Other) {
            return std::nullopt;
        }
        const TVal& base = s.reg(op.base);
        if (base.is(TVal::Kind::Stack)) {
            return std::pair{base.base, base.a + op.disp};
        }
        if (op.base == Reg::Rbp && base.is(TVal::Kind::Unknown)) {
            return std::pair{Reg::Rbp, op.disp};
        }
        return std::nullopt;
    }

    TVal readReg(const State& s, Reg r) const {
        if (r == Reg::Rsp) {
            return TVal::stack(Reg::Rsp, -s.rspDelta);
        }
        if (r == Reg::None || r == Reg::Other || r == Reg::Rip) {
            return {};
        }
        return s.reg(r);
    }

    TVal read(const functions::Function& fn, const Instruction& insn, const Operand& op, State& s) {
        switch (op.kind) {
        case Operand::Kind::Register: return readReg(s, op.reg);
        case Operand::Kind::Immediate: return insn.immediateRef ? TVal{} : TVal::constant(op.imm);
        case Operand::Kind::Memory: return load(fn, insn, op, s);
        default: return {};
        }
    }

    TVal load(const functions::Function& fn, const Instruction& insn, const Operand& op, State& s) {
        if (op.base == Reg::Rip || op.base == Reg::None || op.base == Reg::Other) {
            // The MmUserProbeAddress import (a pointer to the user/kernel boundary).
            if (insn.memoryRef && m_probeLimitSlots.count(*insn.memoryRef)) {
                return TVal{TVal::Kind::ProbeLimitPtr};
            }
            return {};
        }
        if (auto slot = slotFor(s, op)) {
            return s.slot(slot->first, slot->second);
        }
        const TVal base = readReg(s, op.base);
        const TVal index = op.index != Reg::None ? readReg(s, op.index) : TVal{};

        if (base.is(TVal::Kind::ProbeLimitPtr) && op.index == Reg::None && op.disp == 0) {
            return TVal{TVal::Kind::ProbeLimit};
        }
        if (op.index == Reg::None) {
            // IRP and IO_STACK_LOCATION fields (x64 offsets, wdm.h).
            if (base.is(TVal::Kind::Irp)) {
                switch (op.disp) {
                case 0x18:
                    // For IRP_MJ_WRITE the field only holds the caller's data
                    // with buffered I/O, which this analysis can't confirm
                    // (file systems and direct-I/O drivers use it for other
                    // things), so writes are traced by their length only.
                    if (m_entry->kind == EntryKind::Write) {
                        return {};
                    }
                    return TVal::data(kUserBuffer, origin("Irp->AssociatedIrp.SystemBuffer", insn.rva));
                case 0x40: // RequestorMode (a byte at the start of the 8-byte slot)
                    m_requestorModeRead = true;
                    return {};
                case 0x70:
                    if (m_entry->kind == EntryKind::Write) {
                        return {};
                    }
                    return userPointerSource("Irp->UserBuffer", insn.rva);
                case 0xB8: return TVal{TVal::Kind::IrpStack};
                default: return {};
                }
            }
            if (base.is(TVal::Kind::IrpStack)) {
                const bool write = m_entry->kind == EntryKind::Write;
                switch (op.disp) {
                case 0x08:
                    return TVal::data(kUserLength,
                                      origin(write ? "IrpSp->Parameters.Write.Length"
                                                   : "IrpSp->Parameters.DeviceIoControl.OutputBufferLength",
                                             insn.rva));
                case 0x10:
                    return write ? TVal{}
                                 : TVal::data(kUserLength,
                                              origin("IrpSp->Parameters.DeviceIoControl.InputBufferLength", insn.rva));
                case 0x20:
                    return write ? TVal{}
                                 : userPointerSource("IrpSp->Parameters.DeviceIoControl.Type3InputBuffer", insn.rva);
                default: return {};
                }
            }
        }

        // Loads through request-derived addresses. Only a pointer read from
        // request memory (plus constants) counts as "the request chose the
        // address"; offsets and indexes into buffers are left alone because
        // their bounds checks aren't modelled.
        if (!base.tainted()) {
            return {};
        }
        const Origin* src = originOf(base);
        std::string text = "[" + (src ? src->text : std::string("request data"));
        if (op.disp) {
            text += (op.disp < 0 ? " - " : " + ") + hex(static_cast<std::uint64_t>(op.disp < 0 ? -op.disp : op.disp));
        }
        text += "]";
        if ((base.labels & kUserData) && base.loaded && !index.tainted()) {
            report(fn, insn, SinkKind::MemoryRead, "load", Severity::High,
                   "reads from an address taken from the request (arbitrary kernel read)", {operand("address", base)});
        } else if ((base.labels & kUserPointer) && !(base.labels & kUserData) && !probed(base)) {
            report(fn, insn, SinkKind::MemoryRead, "load", Severity::High,
                   "dereferences a user-mode pointer that wasn't checked with ProbeForRead - the caller can pass a "
                   "kernel address",
                   {operand("address", base)});
        }
        TVal result = TVal::data(kUserData, origin(text, insn.rva));
        // Only the first hop counts: data read through a request-chosen
        // pointer is not itself reported as a further chosen address (that
        // would repeat the same problem down a structure).
        result.loaded = !(base.labels & kUserData);
        return result;
    }

    TVal addressOf(const Instruction& insn, const Operand& op, const State& s) const {
        if (insn.memoryRef && insn.memoryRefIsAddressOf) {
            return {};
        }
        if (op.base == Reg::Rsp && op.index == Reg::None) {
            return TVal::stack(Reg::Rsp, op.disp - s.rspDelta);
        }
        if (op.base == Reg::Rbp && op.index == Reg::None && s.reg(Reg::Rbp).is(TVal::Kind::Unknown)) {
            return TVal::stack(Reg::Rbp, op.disp);
        }
        if (op.base == Reg::None || op.base == Reg::Other || op.base == Reg::Rip) {
            return {};
        }
        TVal base = readReg(s, op.base);
        const TVal index = op.index != Reg::None ? readReg(s, op.index) : TVal{};
        if (op.index == Reg::None) {
            if (base.is(TVal::Kind::Stack)) {
                base.a += op.disp;
                return base;
            }
            if (base.is(TVal::Kind::Constant)) {
                return TVal::constant(base.a + op.disp);
            }
            return base.tainted() ? base : TVal{}; // pointer + offset keeps its labels
        }
        if (base.tainted() || index.tainted()) {
            return merge(base, index); // computed address: not "loaded"
        }
        return {};
    }

    TaintedOperand operand(const std::string& name, const TVal& v) const {
        TaintedOperand o;
        o.name = name;
        o.labels = v.labels;
        if (const Origin* src = originOf(v)) {
            o.source = src->text;
            o.sourceAt = src->at;
        }
        return o;
    }

    // ------------------------------------------------------- stores ----

    void store(const functions::Function& fn, const Instruction& insn, const Operand& dst, const TVal& value,
               State& s) {
        if (dst.base == Reg::Rip || dst.base == Reg::None || dst.base == Reg::Other) {
            return;
        }
        if (auto slot = slotFor(s, dst)) {
            s.stack[*slot] = value;
            return;
        }
        if (dst.base == Reg::Rsp) {
            return;
        }
        const TVal base = readReg(s, dst.base);
        const TVal index = dst.index != Reg::None ? readReg(s, dst.index) : TVal{};
        std::vector<TaintedOperand> ops;
        (void)index;
        if ((base.labels & kUserData) && base.loaded) {
            ops.push_back(operand("address", base));
            if (value.tainted()) {
                ops.push_back(operand("value", value));
            }
            report(fn, insn, SinkKind::MemoryWrite, "store", value.tainted() ? Severity::Critical : Severity::High,
                   value.tainted() ? "writes request data to an address taken from the request (write-what-where)"
                                   : "writes to an address taken from the request (arbitrary kernel write)",
                   ops);
        } else if ((base.labels & kUserPointer) && !(base.labels & kUserData) && !probed(base)) {
            ops.push_back(operand("address", base));
            report(fn, insn, SinkKind::MemoryWrite, "store", Severity::High,
                   "writes through a user-mode pointer that wasn't checked with ProbeForWrite - the caller can "
                   "pass a kernel address",
                   ops);
        }
    }

    // -------------------------------------------------------- steps ----

    void step(const functions::Function& fn, const Instruction& insn, State& s, int depth) {
        if (insn.flow == Flow::Call) {
            call(fn, insn, s, depth);
            return;
        }
        const std::string& m = insn.mnemonic;
        if (m == "wrmsr" || m == "rdmsr") {
            privileged(fn, insn, s);
            return;
        }
        if (insn.hasRepPrefix && (m.rfind("rep movs", 0) == 0 || m.rfind("rep stos", 0) == 0)) {
            repString(fn, insn, s);
            return;
        }
        if (m == "in" || m == "out" || m.rfind("ins", 0) == 0 || m.rfind("outs", 0) == 0) {
            if (m == "in" || m == "out") {
                privileged(fn, insn, s);
            }
            if (m == "in") {
                s.reg(Reg::Rax) = {};
            }
            return;
        }
        if (insn.opCount == 0) {
            return;
        }
        const Operand& dst = insn.ops[0];
        constexpr std::int64_t ptr = 8;
        if (m == "push") {
            s.rspDelta += ptr;
            s.stack[{Reg::Rsp, -s.rspDelta}] = read(fn, insn, dst, s);
            return;
        }
        if (m == "pop") {
            s.rspDelta -= ptr;
            return;
        }
        if ((m == "sub" || m == "add") && dst.kind == Operand::Kind::Register && dst.reg == Reg::Rsp &&
            insn.opCount == 2 && insn.ops[1].kind == Operand::Kind::Immediate) {
            s.rspDelta += m == "sub" ? insn.ops[1].imm : -insn.ops[1].imm;
            return;
        }
        if (m == "mov" && dst.kind == Operand::Kind::Register && dst.reg == Reg::Other && insn.opCount == 2 &&
            insn.ops[1].kind == Operand::Kind::Register) {
            // mov crN / drN, reg
            if (insn.operands.rfind("cr", 0) == 0 || insn.operands.rfind("dr", 0) == 0) {
                const TVal v = readReg(s, insn.ops[1].reg);
                if (v.tainted()) {
                    const bool cr = insn.operands.rfind("cr", 0) == 0;
                    report(fn, insn, SinkKind::Instruction, "mov " + insn.operands.substr(0, 3),
                           cr ? Severity::Critical : Severity::High,
                           cr ? "writes a control register with request data (e.g. disables SMEP/write protection)"
                              : "writes a debug register with request data",
                           {operand("source", v)});
                }
            }
            return;
        }
        if (m == "cmp" && insn.opCount == 2) {
            inlineProbe(fn, insn, s);
        }
        if (m == "cmp" || m == "test" || m == "bt" || m.rfind("j", 0) == 0 || m.rfind("set", 0) == 0 ||
            m == "nop" || m.rfind("prefetch", 0) == 0) {
            if (m.rfind("set", 0) == 0 && dst.kind == Operand::Kind::Register) {
                s.reg(dst.reg) = {};
            }
            // Reads of memory operands still matter (a cmp through a user pointer is a dereference).
            for (std::uint8_t i = 0; i < insn.opCount; ++i) {
                if (insn.ops[i].kind == Operand::Kind::Memory && m != "nop" && m.rfind("prefetch", 0) != 0) {
                    load(fn, insn, insn.ops[i], s);
                }
            }
            return;
        }

        const bool isMov = m == "mov" || m == "movabs" || m == "movzx" || m == "movsx" || m == "movsxd" ||
                           m == "movd" || m == "movq";
        if (dst.kind == Operand::Kind::Memory) {
            TVal value;
            if (m.rfind("mov", 0) == 0 && insn.opCount > 1) {
                value = read(fn, insn, insn.ops[1], s); // includes movups/movdqa stores of vector registers
            } else if (insn.opCount > 1) {
                // add [mem], reg etc.: the result mixes both.
                value = merge(load(fn, insn, dst, s), read(fn, insn, insn.ops[1], s));
            }
            store(fn, insn, dst, value, s);
            return;
        }
        if (dst.kind != Operand::Kind::Register || dst.reg == Reg::None || dst.reg == Reg::Other ||
            dst.reg == Reg::Rsp || dst.reg == Reg::Rip) {
            // Vector registers etc.: still evaluate memory sources for dereference checks.
            for (std::uint8_t i = 1; i < insn.opCount; ++i) {
                if (insn.ops[i].kind == Operand::Kind::Memory) {
                    load(fn, insn, insn.ops[i], s);
                }
            }
            return;
        }

        TVal& d = s.reg(dst.reg);
        if (isMov && insn.opCount > 1) {
            d = read(fn, insn, insn.ops[1], s);
            return;
        }
        if (m == "lea" && insn.opCount > 1) {
            d = addressOf(insn, insn.ops[1], s);
            return;
        }
        if ((m == "xor" || m == "sub") && insn.opCount > 1 && insn.ops[1].kind == Operand::Kind::Register &&
            insn.ops[1].reg == dst.reg) {
            d = TVal::constant(0);
            return;
        }
        if (m.rfind("cmov", 0) == 0 && insn.opCount > 1) {
            d = merge(d, read(fn, insn, insn.ops[1], s));
            return;
        }
        if (m == "imul" && insn.opCount == 3) {
            const TVal src = read(fn, insn, insn.ops[1], s);
            d = src.tainted() ? TVal::data(src.labels, src.origin) : TVal{};
            return;
        }
        static const std::set<std::string> kBinary{"add", "sub", "and", "or", "xor", "adc", "sbb", "imul",
                                                   "shl", "shr", "sar", "rol", "ror", "sal"};
        static const std::set<std::string> kUnary{"inc", "dec", "neg", "not", "bswap"};
        if (kBinary.count(m) && insn.opCount > 1) {
            const TVal src = read(fn, insn, insn.ops[1], s);
            if (d.is(TVal::Kind::Constant) && src.is(TVal::Kind::Constant)) {
                std::int64_t v = d.a;
                if (m == "add") v += src.a;
                else if (m == "sub") v -= src.a;
                else if (m == "and") v &= src.a;
                else if (m == "or") v |= src.a;
                else if (m == "xor") v ^= src.a;
                else if (m == "shl" || m == "sal") v <<= (src.a & 63);
                else if (m == "shr") v = static_cast<std::int64_t>(static_cast<std::uint64_t>(v) >> (src.a & 63));
                else { d = {}; return; }
                d = TVal::constant(v);
                return;
            }
            if (d.is(TVal::Kind::Stack) && src.is(TVal::Kind::Constant) && (m == "add" || m == "sub")) {
                d.a += m == "add" ? src.a : -src.a;
                return;
            }
            if (d.tainted() && src.is(TVal::Kind::Constant) && (m == "add" || m == "sub")) {
                return; // pointer/length plus a constant keeps its labels
            }
            if (d.tainted() || src.tainted()) {
                TVal r = merge(d, src);
                // Pointer arithmetic with request data gives a request-chosen address.
                if ((d.labels & (kUserBuffer | kUserPointer)) && src.tainted()) {
                    r.labels |= kUserData;
                }
                d = r;
            } else {
                d = {};
            }
            return;
        }
        if (kUnary.count(m)) {
            if (d.is(TVal::Kind::Constant)) {
                if (m == "inc") d.a += 1;
                else if (m == "dec") d.a -= 1;
                else if (m == "neg") d.a = -d.a;
                else if (m == "not") d.a = ~d.a;
                else d = {};
            }
            return; // labels are kept
        }
        // Anything else that writes the register: unknown, but keep taint
        // from register/memory sources (conversions, shifts by cl, ...).
        TVal r;
        for (std::uint8_t i = 1; i < insn.opCount; ++i) {
            r = merge(r, read(fn, insn, insn.ops[i], s));
        }
        d = r.tainted() ? r : TVal{};
    }

    // `cmp ptr, MmUserProbeAddress` (or the constant boundary) is how
    // ProbeForRead/ProbeForWrite are inlined: treat the pointer as probed.
    void inlineProbe(const functions::Function& fn, const Instruction& insn, State& s) {
        auto value = [&](const Operand& op) -> TVal {
            if (op.kind == Operand::Kind::Register) {
                return readReg(s, op.reg);
            }
            if (op.kind == Operand::Kind::Immediate) {
                return TVal::constant(op.imm);
            }
            if (op.kind == Operand::Kind::Memory) {
                const bool reporting = m_reporting;
                m_reporting = false; // evaluating the operand, not a new access
                TVal v = load(fn, insn, op, s);
                m_reporting = reporting;
                return v;
            }
            return {};
        };
        auto isLimit = [](const TVal& v) {
            if (v.is(TVal::Kind::ProbeLimit)) {
                return true;
            }
            if (!v.is(TVal::Kind::Constant)) {
                return false;
            }
            const auto c = static_cast<std::uint64_t>(v.a);
            return c == 0x7FFFFFFF0000ull || c == 0x7FFFFFFEFFFFull || c == 0x7FFFFFFFFFFFull;
        };
        const TVal a = value(insn.ops[0]), b = value(insn.ops[1]);
        for (const auto& [ptr, limit] : {std::pair{a, b}, std::pair{b, a}}) {
            if ((ptr.labels & kUserPointer) && isLimit(limit)) {
                markProbed(ptr);
            }
        }
    }

    void privileged(const functions::Function& fn, const Instruction& insn, State& s) {
        const std::string& m = insn.mnemonic;
        std::vector<TaintedOperand> ops;
        auto check = [&](Reg r, const char* name) {
            const TVal& v = s.reg(r);
            if (v.tainted()) {
                ops.push_back(operand(name, v));
            }
            return v.tainted();
        };
        if (m == "wrmsr") {
            const bool index = check(Reg::Rcx, "ecx (MSR number)");
            const bool lo = check(Reg::Rax, "eax (value, low half)");
            const bool hi = check(Reg::Rdx, "edx (value, high half)");
            if (index || lo || hi) {
                report(fn, insn, SinkKind::Instruction, "wrmsr", Severity::Critical,
                       index ? "writes a model-specific register the caller chooses (e.g. LSTAR - code execution)"
                             : "writes request data to a model-specific register",
                       ops);
            }
        } else if (m == "rdmsr") {
            if (check(Reg::Rcx, "ecx (MSR number)")) {
                report(fn, insn, SinkKind::Instruction, "rdmsr", Severity::High,
                       "reads a model-specific register the caller chooses (leaks kernel addresses)", ops);
            }
            s.reg(Reg::Rax) = {};
            s.reg(Reg::Rdx) = {};
        } else if (m == "out") {
            const bool port = check(Reg::Rdx, "dx (port)");
            const bool value = check(Reg::Rax, "al/ax/eax (value)");
            if (port || value) {
                report(fn, insn, SinkKind::Instruction, "out", port ? Severity::High : Severity::Medium,
                       port ? "writes to an I/O port the caller chooses" : "writes request data to an I/O port",
                       ops);
            }
        } else if (m == "in") {
            if (check(Reg::Rdx, "dx (port)")) {
                report(fn, insn, SinkKind::Instruction, "in", Severity::High,
                       "reads an I/O port the caller chooses", ops);
            }
        }
    }

    void repString(const functions::Function& fn, const Instruction& insn, State& s) {
        const bool movs = insn.mnemonic.rfind("rep movs", 0) == 0;
        std::vector<TaintedOperand> ops;
        Severity sev = Severity::Medium;
        std::string impact;
        const TVal dst = s.reg(Reg::Rdi), count = s.reg(Reg::Rcx), src = s.reg(Reg::Rsi);
        if ((dst.labels & kUserData) || ((dst.labels & kUserPointer) && !probed(dst))) {
            ops.push_back(operand("rdi (destination)", dst));
            sev = Severity::Critical;
            impact = "copies/fills memory at an address the caller chooses";
        }
        if (count.labels & (kUserData | kUserLength)) {
            ops.push_back(operand("rcx (count)", count));
            if (impact.empty()) {
                sev = Severity::High;
                impact = "inline copy/fill with a length chosen by the caller - overflows unless checked";
            }
        }
        if (movs && ((src.labels & kUserData) || ((src.labels & kUserPointer) && !probed(src)))) {
            ops.push_back(operand("rsi (source)", src));
            if (impact.empty()) {
                sev = Severity::High;
                impact = "copies from an address the caller chooses";
            }
        }
        if (!ops.empty()) {
            report(fn, insn, SinkKind::Instruction, insn.mnemonic, sev, impact, ops);
        }
        s.reg(Reg::Rcx) = TVal::constant(0);
        s.reg(Reg::Rdi) = {};
        s.reg(Reg::Rsi) = {};
    }

    TVal argument(const State& s, int index) const {
        if (index < 4) {
            return s.reg(kArgRegs[static_cast<std::size_t>(index)]);
        }
        return s.stackArg(0x20 + 8 * (index - 4));
    }

    void call(const functions::Function& fn, const Instruction& insn, State& s, int depth) {
        std::string import;
        if (insn.memoryRef) {
            if (auto it = m_imports.find(*insn.memoryRef); it != m_imports.end()) {
                import = it->second.substr(it->second.find('!') + 1);
            }
        }
        TVal result;
        if (!import.empty()) {
            importCall(fn, insn, import, s);
        } else if (auto wdf = m_wdfCalls.find(insn.rva); wdf != m_wdfCalls.end()) {
            wdfCall(insn, wdf->second, s);
        } else if (insn.branchTarget && depth < kMaxDepth) {
            if (const auto* callee = m_functions.find(*insn.branchTarget)) {
                State entry;
                for (Reg r : kArgRegs) {
                    const TVal v = s.reg(r);
                    entry.reg(r) = v.is(TVal::Kind::Stack) ? TVal{} : v; // caller frame addresses aren't followed
                }
                for (int k = 0; k < 4; ++k) {
                    const TVal v = s.stackArg(0x20 + 8 * k);
                    entry.stack[{Reg::Rsp, 0x28 + 8 * k}] = v.is(TVal::Kind::Stack) ? TVal{} : v;
                }
                // Walked even without tainted arguments: request data can
                // also come from the IRP the callee reaches some other way,
                // and its sensitive calls are recorded as checked calls.
                m_callSites.push_back(insn.rva);
                result = walkFunction(*callee, entry, depth + 1);
                m_callSites.pop_back();
            }
        }
        for (Reg r : {Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9, Reg::R10, Reg::R11}) {
            s.reg(r) = {};
        }
        s.reg(Reg::Rax) = result;
    }

    void importCall(const functions::Function& fn, const Instruction& insn, const std::string& api, State& s) {
        if (api == "ProbeForRead" || api == "ProbeForWrite") {
            const TVal p = s.reg(Reg::Rcx);
            markProbed(p);
            return;
        }
        const ApiSink* sink = findSink(api);
        if (!sink) {
            return;
        }
        CheckedCall checked;
        checked.api = api;
        checked.at = insn.rva;
        checked.function = fn.rva;
        checked.entry = m_entry->role;
        std::vector<TaintedOperand> ops;
        Severity sev = Severity::Medium;
        std::string impact;
        for (const auto& arg : sink->args) {
            const TVal v = argument(s, arg.index);
            CheckedCall::Arg a;
            a.name = arg.name;
            std::uint32_t hit = v.labels & arg.mask;
            if (!(arg.mask & kUserLength)) {
                // An address argument: the request chose it only if it is a
                // pointer read from request data, or a user-mode pointer
                // that wasn't probed.
                const bool chosen = ((hit & kUserData) && v.loaded) || ((hit & kUserPointer) && !probed(v)) ||
                                    (hit & kUserBuffer);
                if (!chosen) {
                    hit = 0;
                }
            } else if (hit == kUserPointer && probed(v)) {
                hit = 0; // a probed user pointer is the documented way to accept one
            }
            if (hit) {
                a.kind = CheckedCall::Arg::Kind::UserControlled;
                a.labels = v.labels;
                ops.push_back(operand(arg.name, v));
                if (impact.empty() || arg.severity > sev) {
                    sev = arg.severity;
                    impact = arg.impact;
                }
            } else if (v.is(TVal::Kind::Constant)) {
                a.kind = CheckedCall::Arg::Kind::Constant;
                a.value = v.a;
            }
            checked.args.push_back(std::move(a));
        }
        addChecked(std::move(checked));
        if (!ops.empty()) {
            report(fn, insn, SinkKind::ApiArgument, api, sev, impact, ops);
        }
    }

    void wdfCall(const Instruction& insn, const std::string& name, State& s) {
        // WdfRequestRetrieve*Buffer(DriverGlobals, Request, MinimumRequiredSize, Buffer**, Length*)
        const bool input = name == "WdfRequestRetrieveInputBuffer";
        const bool unsafeUser =
            name == "WdfRequestRetrieveUnsafeUserInputBuffer" || name == "WdfRequestRetrieveUnsafeUserOutputBuffer";
        if (!input && !unsafeUser) {
            return;
        }
        const TVal bufferOut = s.reg(Reg::R9);
        const TVal lengthOut = s.stackArg(0x20);
        if (bufferOut.is(TVal::Kind::Stack)) {
            s.stack[{bufferOut.base, bufferOut.a}] =
                input ? TVal::data(kUserBuffer, origin(name + " buffer", insn.rva))
                      : TVal::userPointer(origin(name + " buffer", insn.rva));
        }
        if (lengthOut.is(TVal::Kind::Stack)) {
            s.stack[{lengthOut.base, lengthOut.a}] = TVal::data(kUserLength, origin(name + " length", insn.rva));
        }
    }

    // --------------------------------------------------------- output ----

    void addChecked(CheckedCall c) {
        if (!m_reporting) {
            return;
        }
        for (auto& existing : m_out.checkedCalls) {
            if (existing.at == c.at) {
                if (!existing.anyUserControlled() && c.anyUserControlled()) {
                    existing = std::move(c);
                }
                return;
            }
        }
        m_out.checkedCalls.push_back(std::move(c));
    }

    void report(const functions::Function& fn, const Instruction& insn, SinkKind kind, const std::string& sink,
                Severity severity, const std::string& impact, std::vector<TaintedOperand> ops) {
        if (!m_reporting) {
            return;
        }
        for (const auto& f : m_out.flows) {
            if (f.at == insn.rva && f.sink == sink) {
                return; // already reported from another path or entry
            }
        }
        TaintFlow flow;
        flow.kind = kind;
        flow.sink = sink;
        flow.impact = impact;
        flow.severity = severity;
        flow.at = insn.rva;
        flow.function = fn.rva;
        flow.entry = m_entry->role;
        flow.path = m_path;
        flow.operands = std::move(ops);
        attachIoctls(flow);
        m_out.flows.push_back(std::move(flow));
    }

    // Blocks of `fn` reachable from the block containing `from`.
    static bool reaches(const functions::Function& fn, std::uint64_t from, std::uint64_t to) {
        auto blockOf = [&](std::uint64_t rva) -> const functions::BasicBlock* {
            for (const auto& b : fn.blocks) {
                if (rva >= b.start && rva < b.end) {
                    return &b;
                }
            }
            return nullptr;
        };
        const auto* start = blockOf(from);
        if (!start) {
            return false;
        }
        std::set<std::uint64_t> seen{start->start};
        std::deque<const functions::BasicBlock*> work{start};
        while (!work.empty()) {
            const auto* b = work.front();
            work.pop_front();
            if (to >= b->start && to < b->end) {
                return true;
            }
            for (std::uint64_t succ : b->successors) {
                if (seen.insert(succ).second) {
                    if (const auto* nb = blockOf(succ)) {
                        work.push_back(nb);
                    }
                }
            }
        }
        return false;
    }

    // The IOCTL codes whose case leads to the flow: from the sink up the
    // call path, the first function that compares codes decides.
    void attachIoctls(TaintFlow& flow) const {
        for (std::size_t k = flow.path.size(); k-- > 0;) {
            const std::uint64_t fnRva = flow.path[k];
            const std::uint64_t loc = k + 1 == flow.path.size() ? flow.at : m_callSites[k];
            const auto* fn = m_functions.find(fnRva);
            if (!fn) {
                continue;
            }
            std::vector<std::uint32_t> exact, compared;
            bool anyCase = false;
            for (const auto& e : m_ioctls.ioctls) {
                if (e.comparedIn != fnRva) {
                    continue;
                }
                compared.push_back(e.decoded.code);
                if (e.caseTarget) {
                    anyCase = true;
                    if (reaches(*fn, *e.caseTarget, loc)) {
                        exact.push_back(e.decoded.code);
                    }
                }
            }
            if (!exact.empty()) {
                flow.ioctls = exact;
                flow.ioctlsExact = true;
                return;
            }
            if (!compared.empty() && !anyCase) {
                flow.ioctls = compared;
                return;
            }
        }
    }

    const functions::FunctionSet& m_functions;
    const ioctl::IoctlAnalysis& m_ioctls;
    DataFlowAnalysis& m_out;
    std::unordered_map<std::uint64_t, std::string> m_imports;
    std::unordered_map<std::uint64_t, std::string> m_wdfCalls;
    std::set<std::uint64_t> m_probeLimitSlots; // IAT slots of MmUserProbeAddress

    const Entry* m_entry = nullptr;
    std::vector<Origin> m_origins;
    std::map<std::pair<std::string, std::uint64_t>, int> m_originIds;
    bool m_reporting = true; // false during fixpoint iterations
    std::set<int> m_probed;
    std::unordered_map<std::string, TVal> m_memo;
    std::vector<std::uint64_t> m_path;
    std::vector<std::uint64_t> m_callSites; // m_callSites[k]: call in m_path[k] to m_path[k + 1]
    std::size_t m_walks = 0;
    bool m_requestorModeRead = false;
    std::size_t m_steps = 0;
    std::size_t m_totalWalks = 0;
};

std::vector<Entry> findEntries(const driver::DriverAnalysis& driver, const functions::FunctionSet& functions) {
    std::vector<Entry> entries;
    std::set<std::pair<std::uint64_t, int>> seen;
    auto add = [&](std::string role, std::uint64_t fn, EntryKind kind) {
        if (functions.find(fn) && seen.insert({fn, static_cast<int>(kind)}).second) {
            entries.push_back({std::move(role), fn, kind});
        }
    };
    for (const auto& m : driver.majorFunctions) {
        if (m.major == 0x0E) add("IRP_MJ_DEVICE_CONTROL", m.handler, EntryKind::DeviceControl);
        if (m.major == 0x0F) add("IRP_MJ_INTERNAL_DEVICE_CONTROL", m.handler, EntryKind::InternalDeviceControl);
        if (m.major == 0x04) add("IRP_MJ_WRITE", m.handler, EntryKind::Write);
    }
    for (const auto& q : driver.wdfQueues) {
        for (const auto& cb : q.callbacks) {
            if (cb.name == "EvtIoDeviceControl") add(cb.name, cb.function, EntryKind::KmdfDeviceControl);
            if (cb.name == "EvtIoInternalDeviceControl") add(cb.name, cb.function, EntryKind::KmdfDeviceControl);
            if (cb.name == "EvtIoWrite") add(cb.name, cb.function, EntryKind::KmdfWrite);
        }
    }
    return entries;
}

} // namespace

DataFlowAnalysis analyzeDataFlow(const pe::PEImage& image, const functions::FunctionSet& functions,
                                 const driver::DriverAnalysis& driver, const ioctl::IoctlAnalysis& ioctls) {
    DataFlowAnalysis out;
    if (image.machine != 0x8664) {
        out.notes.push_back("Data-flow analysis covers x64 drivers only; this image is " + image.machineName + ".");
        return out;
    }
    const auto entries = findEntries(driver, functions);
    if (entries.empty()) {
        out.notes.push_back("No user-request handler (IRP_MJ_DEVICE_CONTROL, IRP_MJ_WRITE, EvtIoDeviceControl, ...) "
                            "was recovered, so no request data was traced.");
        return out;
    }
    Engine engine(image, functions, driver, ioctls, out);
    for (const auto& e : entries) {
        const auto* fn = functions.find(e.function);
        out.entries.push_back(e.role + " (" + (fn ? fn->name : hex(e.function)) + ")");
        engine.run(e);
    }
    out.functionsAnalysed = engine.walks();
    std::stable_sort(out.flows.begin(), out.flows.end(), [](const TaintFlow& a, const TaintFlow& b) {
        return a.severity != b.severity ? a.severity > b.severity : a.at < b.at;
    });
    std::sort(out.checkedCalls.begin(), out.checkedCalls.end(),
              [](const CheckedCall& a, const CheckedCall& b) { return a.at < b.at; });
    out.notes.push_back("Values are followed along control-flow edges and merged where paths meet (not per path), "
                        "and range checks aren't recognised: a flow means the data can reach the operation, not "
                        "that it is unchecked.");
    return out;
}

} // namespace dasa::core::dataflow
