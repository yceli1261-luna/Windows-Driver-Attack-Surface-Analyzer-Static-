#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace dasa::core::disasm {

/// How an instruction affects control flow.
enum class Flow : std::uint8_t {
    Normal,     // falls through to the next instruction
    Call,       // call (direct or indirect); falls through afterwards
    Jump,       // unconditional jmp (direct or indirect)
    CondJump,   // jcc / loop / jrcxz: target or fall through
    Return,     // ret / iret
    Trap,       // int3, ud2, hlt, int 0x29 (__fastfail) - does not continue
};

/// One decoded instruction, addressed by RVA. Capstone types stop at the
/// Disassembler; this is all the rest of core/ sees.
struct Instruction {
    std::uint64_t rva = 0;
    std::uint8_t size = 0;
    std::array<std::uint8_t, 16> bytes{};
    std::string mnemonic;
    std::string operands;
    Flow flow = Flow::Normal;

    // Direct branch/call target (RVA). Unset for indirect transfers.
    std::optional<std::uint64_t> branchTarget;
    // RVA referenced by a RIP-relative memory operand (x64), or by an
    // absolute memory operand inside the image (x86). For `call [rip+X]`
    // this is the IAT slot being called through.
    std::optional<std::uint64_t> memoryRef;
    // An immediate that is a virtual address inside the image (e.g.
    // `mov rax, 0x140001234`), converted to an RVA.
    std::optional<std::uint64_t> immediateRef;
    // `lea reg, [rip+X]`: X as an RVA. Address-of, not a memory access.
    bool memoryRefIsAddressOf = false;

    bool isIndirect() const {
        return (flow == Flow::Call || flow == Flow::Jump) && !branchTarget.has_value();
    }
    std::uint64_t endRva() const { return rva + size; }
    std::string text() const { return operands.empty() ? mnemonic : mnemonic + " " + operands; }
};

} // namespace dasa::core::disasm
