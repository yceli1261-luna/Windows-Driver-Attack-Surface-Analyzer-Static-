#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "core/disasm/Instruction.h"
#include "core/functions/FunctionDiscoverer.h"
#include "core/pe/PEImage.h"

namespace dasa::core::driver {

/// What the tracker knows a register or stack slot holds.
struct Value {
    enum class Kind : std::uint8_t {
        Unknown,
        Immediate,       // a = the constant
        Address,         // a = RVA (lea [rip+X], mov r, imm VA)
        Stack,           // address of a stack slot: base + a
        DriverObject,    // the DRIVER_OBJECT* passed to DriverEntry
        DriverObjectAt,  // DriverObject + a (e.g. &MajorFunction[0])
        DriverExtension, // DriverObject->DriverExtension
        RegistryPath,
        WdfTable,        // the WDF function table pointer (*WdfFunctions_01xxx)
        WdfFunction,     // WdfFunctions[a]
    };
    Kind kind = Kind::Unknown;
    std::int64_t a = 0;
    disasm::Reg base = disasm::Reg::None; // for Stack

    static Value unknown() { return {}; }
    static Value make(Kind k, std::int64_t v = 0) { return {k, v, disasm::Reg::None}; }
    bool is(Kind k) const { return kind == k; }
};

/// Register file plus stack slots, keyed by (frame register, offset).
/// The stack model is per-function and assumes rsp/rbp don't move after the
/// prologue, which holds for MSVC x64 code; pushes mid-function make
/// rsp-relative keys stale (a stated limitation, not a crash).
struct TrackerState {
    std::array<Value, 19> regs{};
    std::map<std::pair<disasm::Reg, std::int64_t>, Value> stack;

    Value& reg(disasm::Reg r) { return regs[static_cast<std::size_t>(r)]; }
    const Value& reg(disasm::Reg r) const { return regs[static_cast<std::size_t>(r)]; }
    Value stackAt(disasm::Reg base, std::int64_t offset) const {
        auto it = stack.find({base, offset});
        return it == stack.end() ? Value{} : it->second;
    }
    /// Reads the slot `offset` bytes into a structure whose address is `structAddr`.
    Value field(const Value& structAddr, std::int64_t offset) const {
        return structAddr.is(Value::Kind::Stack) ? stackAt(structAddr.base, structAddr.a + offset) : Value{};
    }
};

/// What a call instruction resolved to.
struct CallInfo {
    std::optional<std::uint64_t> target; // direct callee RVA (not a CFG thunk)
    std::optional<std::uint32_t> wdfIndex;
    std::string importName;              // "dll!name" for IAT calls
};

class TrackerHooks {
public:
    virtual ~TrackerHooks() = default;
    /// A store to [base + index*scale + disp] where `base` holds `baseValue`.
    virtual void onStore(const disasm::Instruction&, const disasm::Operand& /*dest*/,
                         const Value& /*baseValue*/, const Value& /*stored*/) {}
    /// `rep stos` with the tracked rdi/rax/rcx values.
    virtual void onRepStos(const disasm::Instruction&, const Value& /*rdi*/, const Value& /*rax*/,
                           const Value& /*rcx*/) {}
    /// Before a call; `state` holds the argument registers and stack.
    virtual void onCall(const disasm::Instruction&, const CallInfo&, const TrackerState& /*state*/) {}
};

struct TrackerContext {
    const pe::PEImage* image = nullptr;
    const functions::FunctionSet* functions = nullptr;
    std::unordered_map<std::uint64_t, std::string> imports; // IAT slot RVA -> dll!name
    std::optional<std::uint64_t> wdfTableVariable;          // RVA of WdfFunctions_01xxx
    std::unordered_set<std::uint64_t> cfgDispatchThunks;    // functions that are just `jmp rax`
    bool x64 = true;
};

/// Builds the parts of the context that don't depend on WDF.
TrackerContext makeTrackerContext(const pe::PEImage& image, const functions::FunctionSet& functions);

/// Walks `fn`'s instructions in address order, updating `state` and calling
/// `hooks` at stores, rep stos and calls. Flow-insensitive within the
/// function: values carry across blocks in address order, which matches
/// straight-line setup code (DriverEntry, queue/config initialisation) but
/// can mis-track values that differ per branch.
void trackFunction(const functions::Function& fn, const TrackerContext& ctx, TrackerState& state,
                   TrackerHooks& hooks);

} // namespace dasa::core::driver
