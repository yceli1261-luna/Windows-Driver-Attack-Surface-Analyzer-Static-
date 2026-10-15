#include "core/disasm/Disassembler.h"

#include <algorithm>
#include <stdexcept>

#include <capstone/capstone.h>

namespace dasa::core::disasm {

struct Disassembler::Impl {
    csh handle = 0;
    cs_insn* insn = nullptr; // reused by every decode() call
    std::uint64_t imageBase = 0;
    std::uint64_t imageSize = 0;

    std::optional<std::uint64_t> toRva(std::uint64_t va) const {
        if (va >= imageBase && va < imageBase + imageSize) {
            return va - imageBase;
        }
        return std::nullopt;
    }
};

Disassembler::Disassembler(Arch arch, std::uint64_t imageBase, std::uint64_t imageSize)
    : m_impl(std::make_unique<Impl>()), m_arch(arch) {
    const cs_mode mode = arch == Arch::X64 ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, mode, &m_impl->handle) != CS_ERR_OK) {
        throw std::runtime_error("Capstone initialisation failed");
    }
    cs_option(m_impl->handle, CS_OPT_DETAIL, CS_OPT_ON);
    m_impl->insn = cs_malloc(m_impl->handle);
    m_impl->imageBase = imageBase;
    m_impl->imageSize = imageSize;
}

Disassembler::~Disassembler() {
    if (m_impl->insn != nullptr) {
        cs_free(m_impl->insn, 1);
    }
    if (m_impl->handle != 0) {
        cs_close(&m_impl->handle);
    }
}

std::optional<Instruction> Disassembler::decode(std::span<const std::uint8_t> code,
                                                std::uint64_t rva) const {
    if (code.empty()) {
        return std::nullopt;
    }
    const std::uint8_t* ptr = code.data();
    size_t size = std::min<size_t>(code.size(), 16);
    std::uint64_t address = m_impl->imageBase + rva;
    cs_insn* insn = m_impl->insn;
    if (!cs_disasm_iter(m_impl->handle, &ptr, &size, &address, insn)) {
        return std::nullopt;
    }

    Instruction out;
    out.rva = rva;
    out.size = static_cast<std::uint8_t>(insn->size);
    std::copy_n(insn->bytes, std::min<std::size_t>(insn->size, out.bytes.size()), out.bytes.begin());
    out.mnemonic = insn->mnemonic;
    out.operands = insn->op_str;

    const cs_x86& x86 = insn->detail->x86;
    const csh h = m_impl->handle;

    if (cs_insn_group(h, insn, CS_GRP_RET) || cs_insn_group(h, insn, CS_GRP_IRET)) {
        out.flow = Flow::Return;
    } else if (cs_insn_group(h, insn, CS_GRP_CALL)) {
        out.flow = Flow::Call;
    } else if (cs_insn_group(h, insn, CS_GRP_JUMP)) {
        out.flow = (insn->id == X86_INS_JMP || insn->id == X86_INS_LJMP) ? Flow::Jump : Flow::CondJump;
    } else if (insn->id == X86_INS_INT3 || insn->id == X86_INS_UD2 || insn->id == X86_INS_HLT) {
        out.flow = Flow::Trap;
    } else if (insn->id == X86_INS_INT && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM &&
               x86.operands[0].imm == 0x29) {
        out.flow = Flow::Trap; // __fastfail
    }

    const bool isBranch = out.flow == Flow::Call || out.flow == Flow::Jump || out.flow == Flow::CondJump;
    for (std::uint8_t i = 0; i < x86.op_count; ++i) {
        const cs_x86_op& op = x86.operands[i];
        if (op.type == X86_OP_IMM) {
            const auto target = m_impl->toRva(static_cast<std::uint64_t>(op.imm));
            if (isBranch) {
                out.branchTarget = target;
            } else if (target && m_impl->imageBase != 0) {
                out.immediateRef = target;
            }
        } else if (op.type == X86_OP_MEM) {
            std::optional<std::uint64_t> ref;
            if (op.mem.base == X86_REG_RIP) {
                ref = m_impl->toRva(insn->address + insn->size + static_cast<std::uint64_t>(op.mem.disp));
            } else if (op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID) {
                ref = m_impl->toRva(static_cast<std::uint64_t>(op.mem.disp));
            }
            if (ref) {
                out.memoryRef = ref;
                out.memoryRefIsAddressOf = insn->id == X86_INS_LEA;
            }
        }
    }
    return out;
}

} // namespace dasa::core::disasm
