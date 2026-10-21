#pragma once

#include <cstddef>
#include <vector>

namespace dasa::core::cfg {

/// Layered ("Sugiyama-style") drawing of a directed graph, top to bottom.
/// Used for both control-flow graphs and call graphs; no Qt dependency.
///
/// Steps: back edges found by DFS from the root are reversed, nodes are
/// assigned to layers by longest path, edges spanning several layers get
/// dummy points per layer, layer order is improved by barycenter sweeps to
/// reduce crossings, and x positions are relaxed towards neighbours
/// without overlapping. Good enough for reading a function or a call
/// neighbourhood; not an optimal crossing minimiser.

struct LayoutNode {
    double width = 0;
    double height = 0;
};

struct LayoutEdge {
    std::size_t from = 0;
    std::size_t to = 0;
};

struct Point {
    double x = 0;
    double y = 0;
};

struct PlacedNode {
    double x = 0; // top-left
    double y = 0;
    int layer = 0;
    int order = 0; // position within the layer, left to right
};

struct RoutedEdge {
    std::vector<Point> points; // polyline from the source to the target
    bool backEdge = false;     // goes up (a loop); routed around the right side
};

struct GraphLayout {
    std::vector<PlacedNode> nodes; // same indices as the input nodes
    std::vector<RoutedEdge> edges; // same indices as the input edges
    double width = 0;
    double height = 0;
};

struct LayoutOptions {
    double layerGap = 56; // vertical space between layers
    double nodeGap = 36;  // minimum horizontal space between nodes
};

/// `root` is laid out first (top); nodes unreachable from it are placed by
/// further DFS passes in index order. Edges out of range are ignored.
GraphLayout layoutLayered(const std::vector<LayoutNode>& nodes, const std::vector<LayoutEdge>& edges,
                          std::size_t root = 0, const LayoutOptions& options = {});

} // namespace dasa::core::cfg
