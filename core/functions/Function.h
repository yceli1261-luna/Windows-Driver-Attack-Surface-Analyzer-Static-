#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/disasm/Instruction.h"

namespace dasa::core::functions {

/// Why a function start was believed. A function can have several.
enum FunctionSource : std::uint32_t {
    kEntryPoint = 1u << 0,     // AddressOfEntryPoint
    kExport = 1u << 1,         // export table
    kExceptionTable = 1u << 2, // x64 .pdata RUNTIME_FUNCTION (compiler-emitted)
    kCallTarget = 1u << 3,     // target of a direct call
    kAddressTaken = 1u << 4,   // code address loaded into a register (lea/mov):
                               // callbacks, dispatch routines, thread starts
    kTailCall = 1u << 5,       // target of a jmp that leaves another function
};

std::string describeSources(std::uint32_t sources);

struct BasicBlock {
    std::uint64_t start = 0; // RVA of first instruction
    std::uint64_t end = 0;   // RVA just past the last instruction
    std::uint32_t firstInstruction = 0; // index into Function::instructions
    std::uint32_t instructionCount = 0;
    std::vector<std::uint64_t> successors; // block starts within the function
};

struct CallSite {
    std::uint64_t rva = 0;                // the call instruction
    std::optional<std::uint64_t> target;  // callee RVA, for direct calls
    std::string importName;               // "ntoskrnl.exe!IoCreateDevice" for IAT calls
    bool isTailCall = false;              // jmp to another function
    bool isIndirect() const { return !target && importName.empty(); }
};

struct Function {
    std::uint64_t rva = 0;
    std::string name;
    std::uint32_t sources = 0;

    std::vector<disasm::Instruction> instructions; // sorted by RVA
    std::vector<BasicBlock> blocks;                // sorted by start
    std::vector<CallSite> calls;
    std::vector<std::uint64_t> callers; // RVAs of functions that call this one

    // Lowest and highest+1 instruction address. Bodies can be discontiguous,
    // so this is a span, not a size.
    std::uint64_t lowRva = 0;
    std::uint64_t highRva = 0;
    std::uint64_t codeBytes = 0; // sum of instruction sizes

    // From .pdata when present: the compiler's own [begin, end) range.
    std::optional<std::uint64_t> declaredEnd;

    // An indirect jmp (typically a switch table) whose targets weren't
    // followed - the body may be incomplete.
    bool hasUnresolvedIndirectJump = false;
    // Decoding stopped at invalid bytes or hit the per-function limit.
    bool truncated = false;
};

} // namespace dasa::core::functions
