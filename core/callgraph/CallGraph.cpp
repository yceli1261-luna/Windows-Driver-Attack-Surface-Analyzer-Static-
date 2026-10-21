#include "core/callgraph/CallGraph.h"

#include <algorithm>
#include <map>
#include <set>

namespace dasa::core::callgraph {

std::size_t CallGraph::functionNode(std::uint64_t rva) const {
    const auto it = byRva.find(rva);
    return it == byRva.end() ? nodes.size() : it->second;
}

namespace {

// Tarjan's strongly connected components over function nodes; marks every
// node in a cycle (or with a self edge) as recursive.
void markRecursion(CallGraph& g) {
    const std::size_t n = g.nodes.size();
    std::vector<int> index(n, -1), low(n, 0);
    std::vector<bool> onStack(n, false);
    std::vector<std::size_t> stack;
    int counter = 0;

    for (std::size_t start = 0; start < n; ++start) {
        if (index[start] != -1 || g.nodes[start].kind != CallGraphNode::Kind::Function) {
            continue;
        }
        // Iterative DFS: (node, next out-edge).
        std::vector<std::pair<std::size_t, std::size_t>> work{{start, 0}};
        index[start] = low[start] = counter++;
        stack.push_back(start);
        onStack[start] = true;
        while (!work.empty()) {
            const std::size_t v = work.back().first;
            std::size_t& next = work.back().second;
            if (next < g.out[v].size()) {
                const CallGraphEdge& e = g.edges[g.out[v][next++]];
                const std::size_t w = e.to;
                if (w == v) {
                    g.nodes[v].recursive = true;
                } else if (index[w] == -1) {
                    index[w] = low[w] = counter++;
                    stack.push_back(w);
                    onStack[w] = true;
                    work.push_back({w, 0});
                } else if (onStack[w]) {
                    low[v] = std::min(low[v], index[w]);
                }
                continue;
            }
            if (low[v] == index[v]) {
                std::vector<std::size_t> component;
                std::size_t w;
                do {
                    w = stack.back();
                    stack.pop_back();
                    onStack[w] = false;
                    component.push_back(w);
                } while (w != v);
                if (component.size() > 1) {
                    for (std::size_t c : component) {
                        g.nodes[c].recursive = true;
                    }
                }
            }
            work.pop_back();
            if (!work.empty()) {
                const std::size_t parent = work.back().first;
                low[parent] = std::min(low[parent], low[v]);
            }
        }
    }
}

} // namespace

CallGraph buildCallGraph(const functions::FunctionSet& set,
                         const std::vector<std::pair<std::string, std::uint64_t>>& entryPoints) {
    CallGraph g;
    for (const auto& f : set.functions) {
        g.byRva[f.rva] = g.nodes.size();
        CallGraphNode node;
        node.rva = f.rva;
        node.name = f.name;
        g.nodes.push_back(std::move(node));
    }
    for (const auto& [role, rva] : entryPoints) {
        const std::size_t i = g.functionNode(rva);
        if (i < g.nodes.size()) {
            auto& roots = g.nodes[i].roots;
            if (std::find(roots.begin(), roots.end(), role) == roots.end()) {
                roots.push_back(role);
            }
        }
    }

    // (from, to) -> edge index, so repeated call sites become one edge.
    std::map<std::pair<std::size_t, std::size_t>, std::size_t> edgeIndex;
    auto addEdge = [&](std::size_t from, std::size_t to, bool tail) {
        const auto [it, inserted] = edgeIndex.try_emplace({from, to}, g.edges.size());
        if (inserted) {
            g.edges.push_back({from, to, 0, false});
        }
        auto& e = g.edges[it->second];
        ++e.callSites;
        e.tailCall = e.tailCall || tail;
    };
    for (const auto& f : set.functions) {
        const std::size_t from = g.byRva.at(f.rva);
        for (const auto& c : f.calls) {
            if (c.target) {
                const std::size_t to = g.functionNode(*c.target);
                if (to < g.nodes.size()) {
                    addEdge(from, to, c.isTailCall);
                }
            } else if (!c.importName.empty()) {
                auto it = g.byImport.find(c.importName);
                if (it == g.byImport.end()) {
                    CallGraphNode node;
                    node.kind = CallGraphNode::Kind::Import;
                    const auto bang = c.importName.find('!');
                    node.name = bang == std::string::npos ? c.importName : c.importName.substr(bang + 1);
                    node.library = bang == std::string::npos ? std::string() : c.importName.substr(0, bang);
                    it = g.byImport.emplace(c.importName, g.nodes.size()).first;
                    g.nodes.push_back(std::move(node));
                }
                addEdge(from, it->second, c.isTailCall);
            }
        }
    }

    g.out.assign(g.nodes.size(), {});
    g.in.assign(g.nodes.size(), {});
    for (std::size_t i = 0; i < g.edges.size(); ++i) {
        g.out[g.edges[i].from].push_back(i);
        g.in[g.edges[i].to].push_back(i);
    }
    markRecursion(g);
    return g;
}

Neighborhood neighborhood(const CallGraph& g, std::size_t focus, int calleeDepth, int callerDepth,
                          ImportScope imports, std::size_t maxNodes) {
    Neighborhood nb;
    if (focus >= g.nodes.size()) {
        return nb;
    }
    std::vector<bool> included(g.nodes.size(), false);
    auto include = [&](std::size_t v) {
        if (included[v]) {
            return true;
        }
        if (nb.nodes.size() >= maxNodes) {
            nb.truncated = true;
            return false;
        }
        included[v] = true;
        nb.nodes.push_back(v);
        return true;
    };
    include(focus);

    // Breadth-first in one direction, functions only; imports are added
    // afterwards for every included function so they never use up depth.
    auto walk = [&](int depth, bool down) {
        std::vector<std::size_t> frontier{focus};
        std::vector<bool> seen(g.nodes.size(), false);
        seen[focus] = true;
        for (int d = 0; d < depth && !frontier.empty(); ++d) {
            std::vector<std::size_t> next;
            for (std::size_t v : frontier) {
                for (std::size_t ei : down ? g.out[v] : g.in[v]) {
                    const std::size_t w = down ? g.edges[ei].to : g.edges[ei].from;
                    if (seen[w] || g.nodes[w].kind != CallGraphNode::Kind::Function) {
                        continue;
                    }
                    seen[w] = true;
                    if (include(w)) {
                        next.push_back(w);
                    }
                }
            }
            frontier = std::move(next);
        }
    };
    walk(calleeDepth, true);
    walk(callerDepth, false);

    if (imports != ImportScope::None) {
        const std::vector<std::size_t> functionsIncluded =
            imports == ImportScope::All ? nb.nodes : std::vector<std::size_t>{focus};
        for (std::size_t v : functionsIncluded) {
            for (std::size_t ei : g.out[v]) {
                const std::size_t w = g.edges[ei].to;
                if (g.nodes[w].kind == CallGraphNode::Kind::Import) {
                    include(w);
                }
            }
        }
    }

    for (std::size_t i = 0; i < g.edges.size(); ++i) {
        if (included[g.edges[i].from] && included[g.edges[i].to]) {
            nb.edges.push_back(i);
        }
    }
    return nb;
}

} // namespace dasa::core::callgraph
