#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "core/disasm/Disassembler.h"

// Encodings and expected decodes follow the Intel SDM; none of the expected
// values come from Capstone or DASA output.

using namespace dasa::core::disasm;

namespace {

constexpr std::uint64_t kBase = 0x140000000ull;
constexpr std::uint64_t kSize = 0x10000;

Instruction decodeOk(const Disassembler& d, std::vector<std::uint8_t> bytes, std::uint64_t rva) {
    auto insn = d.decode(bytes, rva);
    EXPECT_TRUE(insn.has_value());
    return insn.value_or(Instruction{});
}

} // namespace

TEST(Disassembler, PlainInstruction) {
    Disassembler d(Arch::X64, kBase, kSize);
    const auto insn = decodeOk(d, {0x48, 0x83, 0xEC, 0x28}, 0x1000);
    EXPECT_EQ(insn.size, 4);
    EXPECT_EQ(insn.mnemonic, "sub");
    EXPECT_EQ(insn.operands, "rsp, 0x28");
    EXPECT_EQ(insn.flow, Flow::Normal);
    EXPECT_FALSE(insn.branchTarget.has_value());
}

TEST(Disassembler, ReturnAndTraps) {
    Disassembler d(Arch::X64, kBase, kSize);
    EXPECT_EQ(decodeOk(d, {0xC3}, 0x1000).flow, Flow::Return);
    EXPECT_EQ(decodeOk(d, {0xCC}, 0x1000).flow, Flow::Trap);       // int3
    EXPECT_EQ(decodeOk(d, {0x0F, 0x0B}, 0x1000).flow, Flow::Trap); // ud2
    EXPECT_EQ(decodeOk(d, {0xCD, 0x29}, 0x1000).flow, Flow::Trap); // int 0x29 (__fastfail)
}

TEST(Disassembler, DirectCallTargetIsRva) {
    Disassembler d(Arch::X64, kBase, kSize);
    // call rel32 = +0x10 from the end of the 5-byte instruction at 0x1000.
    const auto insn = decodeOk(d, {0xE8, 0x10, 0x00, 0x00, 0x00}, 0x1000);
    EXPECT_EQ(insn.flow, Flow::Call);
    ASSERT_TRUE(insn.branchTarget.has_value());
    EXPECT_EQ(*insn.branchTarget, 0x1015u);
    EXPECT_FALSE(insn.isIndirect());
}

TEST(Disassembler, RipRelativeCallThroughIat) {
    Disassembler d(Arch::X64, kBase, kSize);
    // call qword ptr [rip+0x100]; 6 bytes at 0x1000 -> slot at 0x1106.
    const auto insn = decodeOk(d, {0xFF, 0x15, 0x00, 0x01, 0x00, 0x00}, 0x1000);
    EXPECT_EQ(insn.flow, Flow::Call);
    EXPECT_TRUE(insn.isIndirect());
    ASSERT_TRUE(insn.memoryRef.has_value());
    EXPECT_EQ(*insn.memoryRef, 0x1106u);
    EXPECT_FALSE(insn.memoryRefIsAddressOf);
}

TEST(Disassembler, LeaIsAddressOf) {
    Disassembler d(Arch::X64, kBase, kSize);
    // lea rax, [rip+0x20]; 7 bytes at 0x2000 -> 0x2027.
    const auto insn = decodeOk(d, {0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00}, 0x2000);
    EXPECT_EQ(insn.mnemonic, "lea");
    ASSERT_TRUE(insn.memoryRef.has_value());
    EXPECT_EQ(*insn.memoryRef, 0x2027u);
    EXPECT_TRUE(insn.memoryRefIsAddressOf);
}

TEST(Disassembler, ConditionalAndUnconditionalJumps) {
    Disassembler d(Arch::X64, kBase, kSize);
    // je rel32 = -0x10 from the end of the 6-byte instruction at 0x3000.
    const auto je = decodeOk(d, {0x0F, 0x84, 0xF0, 0xFF, 0xFF, 0xFF}, 0x3000);
    EXPECT_EQ(je.flow, Flow::CondJump);
    ASSERT_TRUE(je.branchTarget.has_value());
    EXPECT_EQ(*je.branchTarget, 0x2FF6u);

    const auto jmp = decodeOk(d, {0xEB, 0x02}, 0x3000); // jmp short +2
    EXPECT_EQ(jmp.flow, Flow::Jump);
    EXPECT_EQ(jmp.branchTarget.value_or(0), 0x3004u);

    const auto jmpReg = decodeOk(d, {0xFF, 0xE0}, 0x3000); // jmp rax
    EXPECT_EQ(jmpReg.flow, Flow::Jump);
    EXPECT_TRUE(jmpReg.isIndirect());
}

TEST(Disassembler, InImageImmediateBecomesReference) {
    Disassembler d(Arch::X64, kBase, kSize);
    // mov rax, 0x140005000 -> RVA 0x5000.
    const auto insn =
        decodeOk(d, {0x48, 0xB8, 0x00, 0x50, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00}, 0x1000);
    ASSERT_TRUE(insn.immediateRef.has_value());
    EXPECT_EQ(*insn.immediateRef, 0x5000u);

    // An immediate outside the image is just a number.
    const auto plain = decodeOk(d, {0xB8, 0x10, 0x00, 0x00, 0xC0}, 0x1000); // mov eax, 0xC0000010
    EXPECT_FALSE(plain.immediateRef.has_value());
}

TEST(Disassembler, X86AbsoluteCallThroughIat) {
    Disassembler d(Arch::X86, 0x10000, 0x8000);
    // call dword ptr [0x12000] -> IAT slot at RVA 0x2000.
    const auto insn = decodeOk(d, {0xFF, 0x15, 0x00, 0x20, 0x01, 0x00}, 0x1000);
    EXPECT_EQ(insn.flow, Flow::Call);
    EXPECT_EQ(insn.memoryRef.value_or(0), 0x2000u);
}

TEST(Disassembler, InvalidBytes) {
    Disassembler d(Arch::X64, kBase, kSize);
    EXPECT_FALSE(d.decode(std::vector<std::uint8_t>{0x06}, 0x1000).has_value()); // push es: invalid in 64-bit
    EXPECT_FALSE(d.decode(std::vector<std::uint8_t>{}, 0x1000).has_value());
}
