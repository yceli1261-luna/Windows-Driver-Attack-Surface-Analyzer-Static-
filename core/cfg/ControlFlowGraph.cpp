#include "core/cfg/ControlFlowGraph.h"

#include <algorithm>

namespace dasa::core::cfg {

using disasm::Flow;

const char* edgeKindName(EdgeKind kind) {
    switch (kind) {
    case EdgeKind::Taken: return "taken";
    case EdgeKind::FallThrough: return "fall-through";
    case EdgeKind::Unconditional: return "jump";
    }
    return "?";
}

const char* blockExitName(BlockExit exit) {
    switch (exit) {
    case BlockExit::None: return "";
    case BlockExit::Return: return "return";
    case BlockExit::Trap: return "trap";
    case BlockExit::TailCall: return "tail call";
    case BlockExit::IndirectJump: return "indirect jump (targets not followed)";
    case BlockExit::NoReturnCall: return "call that does not return";
    }
    return "";
}

std::size_t ControlFlowGraph::blockAt(std::uint64_t rva) const {
    const auto it = std::lower_bound(blocks.begin(), blocks.end(), rva,
                                     [](const functions::BasicBlock* b, std::uint64_t v) { return b->start < v; });
    return it != blocks.end() && (*it)->start == rva ? static_cast<std::size_t>(it - blocks.begin()) : blocks.size();
}

ControlFlowGraph buildControlFlowGraph(const functions::Function& f) {
    ControlFlowGraph g;
    g.function = &f;
    g.blocks.reserve(f.blocks.size());
    for (const auto& b : f.blocks) {
        g.blocks.push_back(&b);
    }
    g.exits.assign(g.blocks.size(), BlockExit::None);
    g.entry = g.blockAt(f.rva);
    if (g.entry == g.blocks.size()) {
        g.entry = 0;
    }

    for (std::size_t i = 0; i < g.blocks.size(); ++i) {
        const auto& b = *g.blocks[i];
        if (b.instructionCount == 0) {
            continue;
        }
        const auto& last = f.instructions[b.firstInstruction + b.instructionCount - 1];
        for (std::uint64_t succ : b.successors) {
            const std::size_t j = g.blockAt(succ);
            if (j == g.blocks.size()) {
                continue;
            }
            EdgeKind kind = EdgeKind::FallThrough;
            if (last.flow == Flow::CondJump) {
                kind = last.branchTarget && *last.branchTarget == succ && succ != last.endRva() ? EdgeKind::Taken
                                                                                                : EdgeKind::FallThrough;
            } else if (last.flow == Flow::Jump) {
                kind = EdgeKind::Unconditional;
            }
            g.edges.push_back({i, j, kind});
        }
        if (!b.successors.empty()) {
            continue;
        }
        switch (last.flow) {
        case Flow::Return: g.exits[i] = BlockExit::Return; break;
        case Flow::Trap: g.exits[i] = BlockExit::Trap; break;
        case Flow::Jump:
            if (last.isIndirect()) {
                // An IAT jmp is a tail call to an import; anything else is
                // an unresolved switch or computed jump.
                const bool importJump = std::any_of(f.calls.begin(), f.calls.end(), [&](const functions::CallSite& c) {
                    return c.rva == last.rva && (c.isTailCall || !c.importName.empty());
                });
                g.exits[i] = importJump ? BlockExit::TailCall : BlockExit::IndirectJump;
            } else {
                g.exits[i] = BlockExit::TailCall; // direct jmp out of the function
            }
            break;
        case Flow::Call: g.exits[i] = BlockExit::NoReturnCall; break;
        default: break;
        }
    }
    return g;
}

} // namespace dasa::core::cfg
