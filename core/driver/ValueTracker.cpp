#include "core/driver/ValueTracker.h"

#include <string_view>

namespace dasa::core::driver {

using disasm::Flow;
using disasm::Instruction;
using disasm::Operand;
using disasm::Reg;
using Kind = Value::Kind;

namespace {

bool isFrameReg(Reg r) {
    return r == Reg::Rsp || r == Reg::Rbp;
}

bool startsWith(std::string_view s, std::string_view prefix) {
    return s.substr(0, prefix.size()) == prefix;
}

class Walker {
public:
    Walker(const TrackerContext& ctx, TrackerState& state, TrackerHooks& hooks)
        : m_ctx(ctx), m_state(state), m_hooks(hooks) {}

    void step(const Instruction& insn) {
        if (insn.flow == Flow::Call) {
            onCall(insn);
            return;
        }
        if (insn.flow == Flow::Return) {
            // Keep the state: blocks laid out after an early return are
            // usually reached from code that ran before it (compilers move
            // the main path below an error-exit), and non-volatile
            // registers such as a saved DriverObject still hold there.
            return;
        }
        if (insn.hasRepPrefix && startsWith(insn.mnemonic, "rep stos")) {
            m_hooks.onRepStos(insn, m_state.reg(Reg::Rdi), m_state.reg(Reg::Rax), m_state.reg(Reg::Rcx));
            m_state.reg(Reg::Rdi) = {};
            m_state.reg(Reg::Rcx) = {};
            return;
        }
        if (insn.opCount == 0) {
            return;
        }
        const Operand& dst = insn.ops[0];
        const std::string& m = insn.mnemonic;

        // These read their first operand rather than writing it.
        if (m == "cmp" || m == "test" || m == "push" || m == "bt" || startsWith(m, "j")) {
            return;
        }
        // `pop` almost always restores a callee-saved register in an
        // epilogue; the restored value is the caller's, which matters only
        // after the return. Ignoring it keeps e.g. a DriverObject saved in rdi
        // valid for blocks laid out after an early-return epilogue.
        if (m == "pop") {
            return;
        }

        if (dst.kind == Operand::Kind::Memory) {
            if (m == "mov" || startsWith(m, "movdq") || startsWith(m, "movup") || startsWith(m, "movap")) {
                const Value stored = (m == "mov" && insn.opCount > 1) ? read(insn, insn.ops[1]) : Value{};
                store(insn, dst, stored);
                // A 16-byte vector store also covers the next 8-byte slot.
                if (m != "mov") {
                    Operand next = dst;
                    next.disp += 8;
                    store(insn, next, Value{}, /*notify=*/false);
                }
            } else {
                // Read-modify-write of memory: the slot's value is no longer known.
                store(insn, dst, Value{}, /*notify=*/false);
            }
            return;
        }

        if (dst.kind != Operand::Kind::Register || dst.reg == Reg::None || dst.reg == Reg::Other) {
            return;
        }
        Value result;
        if ((m == "mov" || m == "movabs") && insn.opCount > 1) {
            result = read(insn, insn.ops[1]);
        } else if (m == "lea" && insn.opCount > 1) {
            result = addressOf(insn, insn.ops[1]);
        } else if (m == "xor" && insn.opCount > 1 && insn.ops[1].kind == Operand::Kind::Register &&
                   insn.ops[1].reg == dst.reg) {
            result = Value::make(Kind::Immediate, 0);
        } else if ((m == "add" || m == "sub") && insn.opCount > 1 &&
                   insn.ops[1].kind == Operand::Kind::Immediate) {
            // Pointer arithmetic on a tracked address keeps it tracked.
            Value v = m_state.reg(dst.reg);
            const std::int64_t delta = m == "add" ? insn.ops[1].imm : -insn.ops[1].imm;
            if (v.is(Kind::Stack) || v.is(Kind::DriverObjectAt) || v.is(Kind::Address)) {
                v.a += delta;
                result = v;
            } else if (v.is(Kind::DriverObject)) {
                result = Value::make(Kind::DriverObjectAt, delta);
            }
        }
        if (dst.reg == Reg::Rsp) {
            return; // stack pointer moves are not modelled
        }
        m_state.reg(dst.reg) = result;
    }

private:
    Value read(const Instruction& insn, const Operand& op) const {
        switch (op.kind) {
        case Operand::Kind::Register:
            return (op.reg == Reg::None || op.reg == Reg::Other) ? Value{} : m_state.reg(op.reg);
        case Operand::Kind::Immediate:
            if (insn.immediateRef) {
                return Value::make(Kind::Address, static_cast<std::int64_t>(*insn.immediateRef));
            }
            return Value::make(Kind::Immediate, op.imm);
        case Operand::Kind::Memory:
            return load(insn, op);
        default:
            return {};
        }
    }

    Value load(const Instruction& insn, const Operand& op) const {
        if (op.base == Reg::Rip || (op.base == Reg::None && op.index == Reg::None)) {
            if (insn.memoryRef && m_ctx.wdfTableVariable && *insn.memoryRef == *m_ctx.wdfTableVariable) {
                return Value::make(Kind::WdfTable);
            }
            return {};
        }
        if (op.index != Reg::None) {
            return {};
        }
        if (isFrameReg(op.base)) {
            return m_state.stackAt(op.base, op.disp);
        }
        const Value& base = m_state.reg(op.base);
        const std::int64_t ptr = m_ctx.x64 ? 8 : 4;
        if (base.is(Kind::WdfTable) && op.disp >= 0 && op.disp % ptr == 0) {
            return Value::make(Kind::WdfFunction, op.disp / ptr);
        }
        if (base.is(Kind::DriverObject) && op.disp == (m_ctx.x64 ? 0x30 : 0x18)) {
            return Value::make(Kind::DriverExtension);
        }
        if (base.is(Kind::Stack)) {
            return m_state.stackAt(base.base, base.a + op.disp);
        }
        return {};
    }

    Value addressOf(const Instruction& insn, const Operand& op) const {
        if (insn.memoryRef && insn.memoryRefIsAddressOf) {
            return Value::make(Kind::Address, static_cast<std::int64_t>(*insn.memoryRef));
        }
        if (op.index != Reg::None) {
            return {};
        }
        if (isFrameReg(op.base)) {
            Value v = Value::make(Kind::Stack, op.disp);
            v.base = op.base;
            return v;
        }
        if (op.base != Reg::None && op.base != Reg::Other) {
            Value base = m_state.reg(op.base);
            if (base.is(Kind::Immediate)) {
                // lea r, [r2 + k] on a known constant: compilers use this
                // for small arithmetic (e.g. lea r15d, [r14 - 1]).
                return Value::make(Kind::Immediate, base.a + op.disp);
            }
            if (base.is(Kind::DriverObject)) {
                return Value::make(Kind::DriverObjectAt, op.disp);
            }
            if (base.is(Kind::DriverObjectAt) || base.is(Kind::Stack)) {
                base.a += op.disp;
                return base;
            }
        }
        return {};
    }

    void store(const Instruction& insn, const Operand& dst, const Value& stored, bool notify = true) {
        if (dst.base == Reg::Rip || dst.base == Reg::None || dst.base == Reg::Other) {
            return;
        }
        if (isFrameReg(dst.base) && dst.index == Reg::None) {
            m_state.stack[{dst.base, dst.disp}] = stored;
            return;
        }
        const Value base = m_state.reg(dst.base);
        if (base.is(Kind::Stack) && dst.index == Reg::None) {
            m_state.stack[{base.base, base.a + dst.disp}] = stored;
            return;
        }
        if (notify) {
            m_hooks.onStore(insn, dst, base, stored);
        }
    }

    void onCall(const Instruction& insn) {
        CallInfo info;
        const Value rax = m_state.reg(Reg::Rax);
        if (insn.branchTarget) {
            if (m_ctx.cfgDispatchThunks.count(*insn.branchTarget) != 0) {
                if (rax.is(Kind::WdfFunction)) {
                    info.wdfIndex = static_cast<std::uint32_t>(rax.a);
                }
            } else {
                info.target = insn.branchTarget;
            }
        } else if (insn.opCount > 0) {
            const Operand& op = insn.ops[0];
            if (op.kind == Operand::Kind::Register && op.reg != Reg::None && op.reg != Reg::Other) {
                const Value v = m_state.reg(op.reg);
                if (v.is(Kind::WdfFunction)) {
                    info.wdfIndex = static_cast<std::uint32_t>(v.a);
                }
            } else if (op.kind == Operand::Kind::Memory) {
                const Value loaded = load(insn, op);
                if (loaded.is(Kind::WdfFunction)) {
                    info.wdfIndex = static_cast<std::uint32_t>(loaded.a); // call [rax+idx*8]
                } else if (insn.memoryRef) {
                    if (auto it = m_ctx.imports.find(*insn.memoryRef); it != m_ctx.imports.end()) {
                        info.importName = it->second;
                    } else if (rax.is(Kind::WdfFunction)) {
                        // call [__guard_dispatch_icall_fptr] with the target in rax
                        info.wdfIndex = static_cast<std::uint32_t>(rax.a);
                    }
                }
            }
        }
        m_hooks.onCall(insn, info, m_state);

        // Volatile registers don't survive the call.
        for (Reg r : {Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9, Reg::R10, Reg::R11}) {
            m_state.reg(r) = {};
        }
    }

    const TrackerContext& m_ctx;
    TrackerState& m_state;
    TrackerHooks& m_hooks;
};

} // namespace

TrackerContext makeTrackerContext(const pe::PEImage& image, const functions::FunctionSet& functions) {
    TrackerContext ctx;
    ctx.image = &image;
    ctx.functions = &functions;
    ctx.imports = functions::buildImportMap(image);
    ctx.x64 = image.machine == 0x8664;
    // Control Flow Guard dispatch thunks: the indirect call target is in rax
    // and the thunk transfers to it - either `jmp rax`
    // (_guard_dispatch_icall_nop) or `jmp [rip+X]` through the
    // __guard_dispatch_icall_fptr slot the loader fills in. A `jmp [iat]`
    // import thunk is not one of these.
    for (const auto& fn : functions.functions) {
        if (fn.instructions.empty()) {
            continue;
        }
        const Instruction& first = fn.instructions.front();
        if (first.flow != Flow::Jump || first.branchTarget || first.opCount != 1) {
            continue;
        }
        const Operand& op = first.ops[0];
        const bool jmpRax = op.kind == Operand::Kind::Register && op.reg == Reg::Rax;
        const bool jmpThroughSlot = op.kind == Operand::Kind::Memory && op.base == Reg::Rip &&
                                    first.memoryRef && ctx.imports.count(*first.memoryRef) == 0;
        if (jmpRax || jmpThroughSlot) {
            ctx.cfgDispatchThunks.insert(fn.rva);
        }
    }
    return ctx;
}

void trackFunction(const functions::Function& fn, const TrackerContext& ctx, TrackerState& state,
                   TrackerHooks& hooks) {
    Walker walker(ctx, state, hooks);
    for (const auto& insn : fn.instructions) {
        walker.step(insn);
    }
}

} // namespace dasa::core::driver
