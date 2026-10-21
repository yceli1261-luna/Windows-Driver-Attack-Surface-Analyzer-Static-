#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/functions/FunctionDiscoverer.h"

namespace dasa::core::callgraph {

struct CallGraphNode {
    enum class Kind { Function, Import };
    Kind kind = Kind::Function;
    std::uint64_t rva = 0;          // Function
    std::string name;               // function name, or the import's name without the DLL
    std::string library;            // Import: "ntoskrnl.exe"
    std::vector<std::string> roots; // entry-point roles: "DriverEntry", "IRP_MJ_DEVICE_CONTROL", ...
    bool recursive = false;         // in a call cycle (including calling itself)
};

struct CallGraphEdge {
    std::size_t from = 0; // node indices
    std::size_t to = 0;
    int callSites = 0;     // number of call instructions from `from` to `to`
    bool tailCall = false; // at least one of them is a tail-call jmp
};

/// Direct calls between the driver's functions and from them to imports.
/// Indirect calls (through registers, the WDF function table, ...) aren't
/// edges here; the KMDF calls are labelled in the Functions listing.
struct CallGraph {
    std::vector<CallGraphNode> nodes;
    std::vector<CallGraphEdge> edges;
    std::vector<std::vector<std::size_t>> out; // edge indices per node
    std::vector<std::vector<std::size_t>> in;
    std::unordered_map<std::uint64_t, std::size_t> byRva;
    std::unordered_map<std::string, std::size_t> byImport; // "ntoskrnl.exe!IoCreateDevice"

    std::size_t functionNode(std::uint64_t rva) const; // nodes.size() if absent
};

/// `entryPoints` are (role, function RVA) pairs, e.g. from
/// KernelApiAnalysis::entryPointFunctions.
CallGraph buildCallGraph(const functions::FunctionSet& functions,
                         const std::vector<std::pair<std::string, std::uint64_t>>& entryPoints);

struct Neighborhood {
    std::vector<std::size_t> nodes; // focus first
    std::vector<std::size_t> edges; // edges among `nodes`
    bool truncated = false;         // stopped at maxNodes
};

/// Which imports a neighbourhood includes.
enum class ImportScope {
    None,
    Focus, // only those the focused function calls
    All,   // those any included function calls
};

/// Functions within `calleeDepth` calls below and `callerDepth` calls
/// above `focus` (breadth-first), plus imports per `imports`. Callee and
/// caller searches each go one direction only, so siblings aren't pulled in.
Neighborhood neighborhood(const CallGraph& graph, std::size_t focus, int calleeDepth, int callerDepth,
                          ImportScope imports, std::size_t maxNodes = 150);

} // namespace dasa::core::callgraph
