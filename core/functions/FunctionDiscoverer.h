#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "core/functions/Function.h"
#include "core/pe/PEImage.h"

namespace dasa::core::functions {

struct FunctionSet {
    std::vector<Function> functions; // sorted by rva

    const Function* find(std::uint64_t rva) const;
    std::size_t totalInstructions() const;

    // Seeds that were rejected because the bytes there don't decode as
    // code (e.g. a code pointer into INT3 padding). Kept for transparency.
    std::vector<std::uint64_t> rejectedSeeds;
};

/// Finds functions in a PE image by recursive-descent disassembly.
///
/// Seeds, in decreasing order of confidence:
///   1. the entry point and exported functions;
///   2. on x64, every primary RUNTIME_FUNCTION in .pdata - compiler-emitted
///      ranges, so these starts are reliable;
///   3. targets of direct calls found while disassembling;
///   4. code addresses loaded into registers (`lea r, [rip+X]`,
///      `mov r, imm` with an in-image VA) - how drivers hand out dispatch
///      routines and callbacks;
///   5. targets of jumps that leave the current function (tail calls).
/// A seed is kept only if it lies in an executable section and its first
/// instruction decodes to something other than a trap/padding byte.
///
/// Known limitations (stated, not hidden):
///   - Functions reached only through computed pointers (tables in .rdata,
///     values built at runtime) and with no .pdata entry are missed.
///   - Indirect jumps (switch tables) are not resolved; the function is
///     marked hasUnresolvedIndirectJump and the cases may be missing.
///   - Without .pdata (x86, or stripped x64), a jmp to an address no other
///     evidence marks as a function is treated as part of the current
///     function, so a tail call into an unknown function can be merged.
///   - Address-taken seeds can be wrong when data happens to look like an
///     in-image code address; the decodability check filters the obvious
///     cases only.
///   - Obfuscated or self-modifying code is out of scope.
FunctionSet discoverFunctions(const pe::PEImage& image);

/// "dll!name" for each IAT slot RVA, for annotating `call [iat]`.
std::unordered_map<std::uint64_t, std::string> buildImportMap(const pe::PEImage& image);

} // namespace dasa::core::functions
