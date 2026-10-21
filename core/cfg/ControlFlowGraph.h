#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/functions/Function.h"

namespace dasa::core::cfg {

/// How control leaves a block along an edge.
enum class EdgeKind {
    Taken,         // conditional branch taken
    FallThrough,   // conditional branch not taken, or straight into the next block
    Unconditional, // jmp
};

const char* edgeKindName(EdgeKind kind);

/// How a block ends when it has no successor inside the function.
enum class BlockExit {
    None,         // continues to successors
    Return,       // ret / iret
    Trap,         // int3, ud2, __fastfail ...
    TailCall,     // jmp to another function or an import
    IndirectJump, // jmp through a register/table whose targets weren't followed
    NoReturnCall, // ends in a call that doesn't return (e.g. KeBugCheckEx)
};

const char* blockExitName(BlockExit exit);

struct CfgEdge {
    std::size_t from = 0; // indices into ControlFlowGraph::blocks
    std::size_t to = 0;
    EdgeKind kind = EdgeKind::FallThrough;
};

/// One function's basic blocks as a graph, with each edge classified from
/// the block's last instruction. Built from the Phase 3 function body, so
/// it has the same limits: switch-table targets aren't followed (blocks
/// ending in such a jump are marked IndirectJump).
struct ControlFlowGraph {
    const functions::Function* function = nullptr;
    std::vector<const functions::BasicBlock*> blocks; // same order as Function::blocks
    std::vector<BlockExit> exits;                     // per block
    std::vector<CfgEdge> edges;
    std::size_t entry = 0; // block starting at the function's RVA

    /// Index of the block starting at `rva`, or blocks.size().
    std::size_t blockAt(std::uint64_t rva) const;
};

ControlFlowGraph buildControlFlowGraph(const functions::Function& function);

} // namespace dasa::core::cfg
