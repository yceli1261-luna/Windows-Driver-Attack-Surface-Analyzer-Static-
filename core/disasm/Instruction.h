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

/// General-purpose registers, normalised to their full-width register
/// (eax, ax, al -> Rax), plus Rip. Anything else (xmm, segment, ...) is
/// Other.
enum class Reg : std::uint8_t {
    None, Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15, Rip, Other
};

struct Operand {
    enum class Kind : std::uint8_t { None, Register, Immediate, Memory };
    Kind kind = Kind::None;
    std::uint8_t size = 0; // bytes
    Reg reg = Reg::None;   // Register
    std::int64_t imm = 0;  // Immediate
    Reg base = Reg::None;  // Memory: [base + index*scale + disp]
    Reg index = Reg::None;
    std::uint8_t scale = 1;
    std::int64_t disp = 0;
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

    // Explicit operands in Intel order (destination first). Implicit
    // operands (e.g. rdi/rcx of `rep stosq`) are not listed.
    std::uint8_t opCount = 0;
    std::array<Operand, 3> ops{};
    bool hasRepPrefix = false;

    bool isIndirect() const {
        return (flow == Flow::Call || flow == Flow::Jump) && !branchTarget.has_value();
    }
    std::uint64_t endRva() const { return rva + size; }
    std::string text() const { return operands.empty() ? mnemonic : mnemonic + " " + operands; }
};

} // namespace dasa::core::disasm
