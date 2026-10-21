#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <set>
#include <string>

#include "analysis/static/StaticAnalysisPipeline.h"
#include "core/callgraph/CallGraph.h"
#include "core/cfg/ControlFlowGraph.h"
#include "core/cfg/GraphLayout.h"

// Graph layout, control-flow graphs and the call graph (Phase 9). Layout
// tests use small graphs built here, with properties that follow from
// their shape. The CFG and call graph tests use DASAWdmSample.sys, whose
// code is written by tests/fixtures/drivers/gen_wdm_fixture.py:
//   0x1000 DriverEntry: RtlInitUnicodeString x3, IoCreateDevice,
//          IoCreateSymbolicLink, MmGetSystemRoutineAddress (all IAT calls)
//   0x1200 DeviceControl: jb 0x1290; sub chain je 0x1260/0x1270/0x1280;
//          ja default; jmp [r8+rcx*8] (switch table); default calls 0x1300
//   0x1300 Helper: cmp edx, imm32 (6 bytes); je 0x1312 (6 bytes);
//          0x130C: xor eax, eax; ret / 0x1312: MmMapIoSpace ... ret
//   0x1400 CreateClose, 0x1410 DriverUnload

namespace fs = std::filesystem;
using namespace dasa;
using namespace dasa::core;

namespace {

fs::path fixture(const char* name) {
    return fs::path(DASA_TEST_FIXTURES_DIR) / "drivers" / name;
}

bool overlaps(const cfg::PlacedNode& a, const cfg::LayoutNode& sa, const cfg::PlacedNode& b,
              const cfg::LayoutNode& sb) {
    return a.x < b.x + sb.width && b.x < a.x + sa.width && a.y < b.y + sb.height && b.y < a.y + sa.height;
}

void expectNoOverlap(const cfg::GraphLayout& l, const std::vector<cfg::LayoutNode>& nodes) {
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        for (std::size_t j = i + 1; j < nodes.size(); ++j) {
            EXPECT_FALSE(overlaps(l.nodes[i], nodes[i], l.nodes[j], nodes[j])) << i << " overlaps " << j;
        }
    }
}

} // namespace

TEST(GraphLayout, DiamondLayersAndRoutes) {
    // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
    const std::vector<cfg::LayoutNode> nodes{{100, 40}, {80, 30}, {120, 50}, {100, 40}};
    const std::vector<cfg::LayoutEdge> edges{{0, 1}, {0, 2}, {1, 3}, {2, 3}};
    const auto l = cfg::layoutLayered(nodes, edges);
    EXPECT_EQ(l.nodes[0].layer, 0);
    EXPECT_EQ(l.nodes[1].layer, 1);
    EXPECT_EQ(l.nodes[2].layer, 1);
    EXPECT_EQ(l.nodes[3].layer, 2);
    EXPECT_LT(l.nodes[0].y + 40, l.nodes[1].y); // layers stack downwards with a gap
    EXPECT_LT(l.nodes[2].y + 50, l.nodes[3].y);
    EXPECT_NE(l.nodes[1].order, l.nodes[2].order);
    expectNoOverlap(l, nodes);
    for (std::size_t i = 0; i < edges.size(); ++i) {
        const auto& e = l.edges[i];
        EXPECT_FALSE(e.backEdge);
        ASSERT_GE(e.points.size(), 2u);
        const auto& src = l.nodes[edges[i].from];
        const auto& dst = l.nodes[edges[i].to];
        EXPECT_DOUBLE_EQ(e.points.front().y, src.y + nodes[edges[i].from].height); // leaves the bottom
        EXPECT_DOUBLE_EQ(e.points.back().y, dst.y);                                 // enters the top
    }
    for (const auto& n : l.nodes) {
        EXPECT_GE(n.x, 0);
        EXPECT_LE(n.x, l.width);
    }
}

TEST(GraphLayout, LoopIsBackEdgeAndLongEdgeBends) {
    // 0 -> 1 -> 2 -> 1 (loop), 0 -> 2 skips a layer, 2 -> 2 self loop
    const std::vector<cfg::LayoutNode> nodes{{60, 20}, {60, 20}, {60, 20}};
    const std::vector<cfg::LayoutEdge> edges{{0, 1}, {1, 2}, {2, 1}, {0, 2}, {2, 2}};
    const auto l = cfg::layoutLayered(nodes, edges);
    EXPECT_EQ(l.nodes[0].layer, 0);
    EXPECT_EQ(l.nodes[1].layer, 1);
    EXPECT_EQ(l.nodes[2].layer, 2);
    EXPECT_FALSE(l.edges[1].backEdge);
    EXPECT_TRUE(l.edges[2].backEdge); // 2 -> 1 goes up
    EXPECT_TRUE(l.edges[4].backEdge); // self loop
    EXPECT_EQ(l.edges[3].points.size(), 4u); // through one dummy: bottom, dummy top/bottom, top
    for (const auto* e : {&l.edges[2], &l.edges[4]}) {
        // Routed to the right of the nodes it connects.
        EXPECT_GT(e->points[1].x, l.nodes[2].x + 60 - 0.001);
    }
    expectNoOverlap(l, nodes);
}

TEST(GraphLayout, DisconnectedAndEmpty) {
    EXPECT_TRUE(cfg::layoutLayered({}, {}).nodes.empty());
    const std::vector<cfg::LayoutNode> nodes{{50, 20}, {50, 20}, {50, 20}};
    const auto l = cfg::layoutLayered(nodes, {{0, 1}, {5, 0}}); // {5, 0} is out of range: ignored
    EXPECT_EQ(l.nodes[2].layer, 0); // unreachable node still placed
    expectNoOverlap(l, nodes);
}

TEST(ControlFlowGraph, WdmHelper) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    const auto* helper = r->functions->find(0x1300);
    ASSERT_NE(helper, nullptr);
    const auto g = cfg::buildControlFlowGraph(*helper);
    ASSERT_EQ(g.blocks.size(), 3u);
    EXPECT_EQ(g.blocks[g.entry]->start, 0x1300u);
    const std::size_t ret0 = g.blockAt(0x130C), body = g.blockAt(0x1312);
    ASSERT_LT(ret0, g.blocks.size());
    ASSERT_LT(body, g.blocks.size());
    ASSERT_EQ(g.edges.size(), 2u);
    std::set<std::pair<std::size_t, cfg::EdgeKind>> out;
    for (const auto& e : g.edges) {
        EXPECT_EQ(e.from, g.entry);
        out.insert({e.to, e.kind});
    }
    EXPECT_TRUE(out.count({body, cfg::EdgeKind::Taken}));        // je 0x1312
    EXPECT_TRUE(out.count({ret0, cfg::EdgeKind::FallThrough}));  // not taken
    EXPECT_EQ(g.exits[ret0], cfg::BlockExit::Return);
    EXPECT_EQ(g.exits[body], cfg::BlockExit::Return);
    EXPECT_EQ(g.exits[g.entry], cfg::BlockExit::None);
}

TEST(ControlFlowGraph, WdmDeviceControl) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    const auto* dc = r->functions->find(0x1200);
    ASSERT_NE(dc, nullptr);
    const auto g = cfg::buildControlFlowGraph(*dc);
    // Every conditional target from the generator is a taken edge.
    for (std::uint64_t target : {0x1290ull, 0x1260ull, 0x1270ull, 0x1280ull}) {
        const std::size_t t = g.blockAt(target);
        ASSERT_LT(t, g.blocks.size()) << std::hex << target;
        EXPECT_TRUE(std::any_of(g.edges.begin(), g.edges.end(), [&](const cfg::CfgEdge& e) {
            return e.to == t && e.kind == cfg::EdgeKind::Taken;
        })) << std::hex << target;
        EXPECT_EQ(g.exits[t], cfg::BlockExit::Return);
    }
    // The switch-table jmp ends a block whose targets weren't followed.
    EXPECT_EQ(std::count(g.exits.begin(), g.exits.end(), cfg::BlockExit::IndirectJump), 1);
}

TEST(CallGraph, WdmFixture) {
    const auto r = analysis::runStaticAnalysis(fixture("DASAWdmSample.sys"));
    const auto g = callgraph::buildCallGraph(*r->functions, r->kernelApis->entryPointFunctions);

    const std::size_t entry = g.functionNode(0x1000), dc = g.functionNode(0x1200), helper = g.functionNode(0x1300);
    ASSERT_LT(entry, g.nodes.size());
    ASSERT_LT(dc, g.nodes.size());
    ASSERT_LT(helper, g.nodes.size());
    auto roots = [&](std::size_t i) { return std::set<std::string>(g.nodes[i].roots.begin(), g.nodes[i].roots.end()); };
    EXPECT_TRUE(roots(entry).count("DriverEntry"));
    EXPECT_TRUE(roots(dc).count("IRP_MJ_DEVICE_CONTROL"));
    EXPECT_TRUE(roots(helper).empty());

    auto edge = [&](std::size_t from, std::size_t to) -> const callgraph::CallGraphEdge* {
        for (std::size_t ei : g.out[from]) {
            if (g.edges[ei].to == to) {
                return &g.edges[ei];
            }
        }
        return nullptr;
    };
    ASSERT_NE(edge(dc, helper), nullptr);
    EXPECT_EQ(edge(dc, helper)->callSites, 1);

    const auto importNode = [&](const std::string& name) {
        for (std::size_t i = 0; i < g.nodes.size(); ++i) {
            if (g.nodes[i].kind == callgraph::CallGraphNode::Kind::Import && g.nodes[i].name == name) {
                return i;
            }
        }
        return g.nodes.size();
    };
    const std::size_t init = importNode("RtlInitUnicodeString"), map = importNode("MmMapIoSpace");
    ASSERT_LT(init, g.nodes.size());
    ASSERT_LT(map, g.nodes.size());
    EXPECT_EQ(g.nodes[map].library, "ntoskrnl.exe");
    ASSERT_NE(edge(entry, init), nullptr);
    EXPECT_EQ(edge(entry, init)->callSites, 3); // three RtlInitUnicodeString calls
    ASSERT_NE(edge(helper, map), nullptr);
    EXPECT_EQ(edge(entry, map), nullptr);
    // DriverEntry makes no direct calls to the driver's own functions.
    for (std::size_t ei : g.out[entry]) {
        EXPECT_EQ(g.nodes[g.edges[ei].to].kind, callgraph::CallGraphNode::Kind::Import);
    }
    for (const auto& n : g.nodes) {
        EXPECT_FALSE(n.recursive) << n.name;
    }

    // Helper's neighbourhood, one call each way.
    auto names = [&](const callgraph::Neighborhood& nb) {
        std::set<std::string> s;
        for (std::size_t v : nb.nodes) {
            s.insert(g.nodes[v].name);
        }
        return s;
    };
    const auto withImports = callgraph::neighborhood(g, helper, 1, 1, callgraph::ImportScope::All);
    EXPECT_EQ(withImports.nodes.front(), helper);
    EXPECT_EQ(names(withImports),
              (std::set<std::string>{g.nodes[helper].name, g.nodes[dc].name, "MmMapIoSpace"}));
    EXPECT_EQ(withImports.edges.size(), 2u);
    const auto noImports = callgraph::neighborhood(g, helper, 1, 1, callgraph::ImportScope::None);
    EXPECT_EQ(names(noImports), (std::set<std::string>{g.nodes[helper].name, g.nodes[dc].name}));
    EXPECT_TRUE(callgraph::neighborhood(g, helper, 1, 1, callgraph::ImportScope::All, 2).truncated);
    // Focus scope: DeviceControl's neighbourhood keeps Helper but not
    // Helper's MmMapIoSpace (DeviceControl itself calls no imports).
    const auto focusOnly = callgraph::neighborhood(g, dc, 1, 0, callgraph::ImportScope::Focus);
    EXPECT_EQ(names(focusOnly), (std::set<std::string>{g.nodes[dc].name, g.nodes[helper].name}));
    const auto all = callgraph::neighborhood(g, dc, 1, 0, callgraph::ImportScope::All);
    EXPECT_TRUE(names(all).count("MmMapIoSpace"));
    const auto entryFocus = callgraph::neighborhood(g, entry, 1, 0, callgraph::ImportScope::Focus);
    EXPECT_TRUE(names(entryFocus).count("IoCreateDevice"));
}

TEST(CallGraph, Recursion) {
    // a -> b -> a (mutual), c -> c (self), d -> a (calls into the cycle only)
    functions::FunctionSet set;
    auto fn = [](std::uint64_t rva, std::vector<std::uint64_t> callees) {
        functions::Function f;
        f.rva = rva;
        f.name = "sub_" + std::to_string(rva);
        for (auto c : callees) {
            functions::CallSite cs;
            cs.target = c;
            f.calls.push_back(cs);
        }
        return f;
    };
    set.functions = {fn(0x10, {0x20}), fn(0x20, {0x10}), fn(0x30, {0x30}), fn(0x40, {0x10})};
    const auto g = callgraph::buildCallGraph(set, {});
    EXPECT_TRUE(g.nodes[g.functionNode(0x10)].recursive);
    EXPECT_TRUE(g.nodes[g.functionNode(0x20)].recursive);
    EXPECT_TRUE(g.nodes[g.functionNode(0x30)].recursive);
    EXPECT_FALSE(g.nodes[g.functionNode(0x40)].recursive);
}
