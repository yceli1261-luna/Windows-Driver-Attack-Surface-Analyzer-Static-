#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "core/disasm/Instruction.h"

namespace dasa::core::disasm {

enum class Arch { X86, X64 };

/// Capstone wrapper for x86/x64 code. Decodes one instruction at a time at
/// a given RVA and classifies its control flow and address references. Not
/// thread-safe: use one instance per thread (they're cheap to create).
class Disassembler {
public:
    /// imageBase/imageSize let the decoder recognise absolute addresses
    /// that point into the image (x86 code, `mov reg, imm64` on x64).
    Disassembler(Arch arch, std::uint64_t imageBase, std::uint64_t imageSize);
    ~Disassembler();
    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    /// Decodes the instruction starting at `code[0]`, which lives at `rva`.
    /// Returns nullopt for bytes that aren't a valid instruction.
    std::optional<Instruction> decode(std::span<const std::uint8_t> code, std::uint64_t rva) const;

    Arch arch() const { return m_arch; }

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    Arch m_arch;
};

} // namespace dasa::core::disasm
