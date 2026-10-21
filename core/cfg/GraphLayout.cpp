#include "core/cfg/GraphLayout.h"

#include <algorithm>
#include <numeric>

namespace dasa::core::cfg {

namespace {

// A layout vertex: a real node or a dummy point on a long edge.
struct Vertex {
    double width = 0;
    double height = 0;
    int layer = 0;
    double x = 0; // centre
    std::vector<std::size_t> up, down; // neighbouring vertices one layer above / below
};

// Edge after cycle removal, pointing down (from lower to higher layer).
struct Segment {
    std::size_t edge = 0;
    bool reversed = false;
    std::vector<std::size_t> chain; // vertices from top to bottom
};

constexpr double kDummyWidth = 8;

} // namespace

GraphLayout layoutLayered(const std::vector<LayoutNode>& nodes, const std::vector<LayoutEdge>& edges,
                          std::size_t root, const LayoutOptions& opt) {
    GraphLayout out;
    const std::size_t n = nodes.size();
    out.nodes.resize(n);
    out.edges.resize(edges.size());
    if (n == 0) {
        return out;
    }

    // ---- 1. back edges: DFS from the root, then from every unvisited node.
    std::vector<std::vector<std::size_t>> outEdges(n);
    for (std::size_t i = 0; i < edges.size(); ++i) {
        if (edges[i].from < n && edges[i].to < n) {
            outEdges[edges[i].from].push_back(i);
        }
    }
    std::vector<bool> isBack(edges.size(), false);
    std::vector<int> state(n, 0); // 0 new, 1 on stack, 2 done
    std::vector<std::size_t> dfsOrder;
    dfsOrder.reserve(n);
    auto dfs = [&](std::size_t start) {
        // Iterative DFS: (node, next out-edge index).
        std::vector<std::pair<std::size_t, std::size_t>> stack{{start, 0}};
        state[start] = 1;
        dfsOrder.push_back(start);
        while (!stack.empty()) {
            auto& [v, next] = stack.back();
            if (next < outEdges[v].size()) {
                const std::size_t e = outEdges[v][next++];
                const std::size_t w = edges[e].to;
                if (state[w] == 1) {
                    isBack[e] = true; // includes self-loops
                } else if (state[w] == 0) {
                    state[w] = 1;
                    dfsOrder.push_back(w);
                    stack.push_back({w, 0});
                }
            } else {
                state[v] = 2;
                stack.pop_back();
            }
        }
    };
    dfs(root < n ? root : 0);
    for (std::size_t v = 0; v < n; ++v) {
        if (state[v] == 0) {
            dfs(v);
        }
    }

    // ---- 2. layers: longest path over the DAG (back edges reversed, self
    // loops dropped), in topological order.
    std::vector<std::vector<std::size_t>> dagSucc(n);
    std::vector<int> indeg(n, 0);
    for (std::size_t i = 0; i < edges.size(); ++i) {
        const auto [a, b] = edges[i];
        if (a >= n || b >= n || a == b) {
            continue;
        }
        const std::size_t from = isBack[i] ? b : a;
        const std::size_t to = isBack[i] ? a : b;
        dagSucc[from].push_back(to);
        ++indeg[to];
    }
    std::vector<int> layer(n, 0);
    {
        std::vector<std::size_t> queue;
        for (std::size_t v : dfsOrder) {
            if (indeg[v] == 0) {
                queue.push_back(v);
            }
        }
        for (std::size_t qi = 0; qi < queue.size(); ++qi) {
            const std::size_t v = queue[qi];
            for (std::size_t w : dagSucc[v]) {
                layer[w] = std::max(layer[w], layer[v] + 1);
                if (--indeg[w] == 0) {
                    queue.push_back(w);
                }
            }
        }
    }

    // ---- 3. vertices: real nodes, then a dummy per crossed layer.
    std::vector<Vertex> vx(n);
    for (std::size_t v = 0; v < n; ++v) {
        vx[v].width = nodes[v].width;
        vx[v].height = nodes[v].height;
        vx[v].layer = layer[v];
    }
    std::vector<Segment> segments;
    for (std::size_t i = 0; i < edges.size(); ++i) {
        const auto [a, b] = edges[i];
        if (a >= n || b >= n || a == b) {
            continue;
        }
        Segment s;
        s.edge = i;
        s.reversed = isBack[i];
        const std::size_t top = s.reversed ? b : a;
        const std::size_t bottom = s.reversed ? a : b;
        s.chain.push_back(top);
        for (int l = layer[top] + 1; l < layer[bottom]; ++l) {
            Vertex d;
            d.width = kDummyWidth;
            d.layer = l;
            vx.push_back(d);
            s.chain.push_back(vx.size() - 1);
        }
        s.chain.push_back(bottom);
        for (std::size_t k = 0; k + 1 < s.chain.size(); ++k) {
            vx[s.chain[k]].down.push_back(s.chain[k + 1]);
            vx[s.chain[k + 1]].up.push_back(s.chain[k]);
        }
        segments.push_back(std::move(s));
    }

    const int layerCount = 1 + std::accumulate(vx.begin(), vx.end(), 0,
                                               [](int m, const Vertex& v) { return std::max(m, v.layer); });
    std::vector<std::vector<std::size_t>> layers(static_cast<std::size_t>(layerCount));
    // Initial order: real nodes in DFS order (keeps fall-through paths
    // left), dummies after the vertex that created them.
    {
        std::vector<std::size_t> rank(vx.size());
        std::size_t r = 0;
        for (std::size_t v : dfsOrder) {
            rank[v] = r++;
        }
        for (std::size_t v = n; v < vx.size(); ++v) {
            rank[v] = r++;
        }
        std::vector<std::size_t> all(vx.size());
        std::iota(all.begin(), all.end(), 0);
        std::sort(all.begin(), all.end(), [&](std::size_t a, std::size_t b) { return rank[a] < rank[b]; });
        for (std::size_t v : all) {
            layers[static_cast<std::size_t>(vx[v].layer)].push_back(v);
        }
    }

    // ---- 4. crossing reduction: barycenter sweeps down and up.
    std::vector<double> pos(vx.size(), 0);
    auto renumber = [&](const std::vector<std::size_t>& L) {
        for (std::size_t i = 0; i < L.size(); ++i) {
            pos[L[i]] = static_cast<double>(i);
        }
    };
    for (const auto& L : layers) {
        renumber(L);
    }
    auto sweep = [&](std::size_t li, bool useUp) {
        auto& L = layers[li];
        std::vector<std::pair<double, std::size_t>> keyed;
        keyed.reserve(L.size());
        for (std::size_t v : L) {
            const auto& nb = useUp ? vx[v].up : vx[v].down;
            double key = pos[v];
            if (!nb.empty()) {
                double sum = 0;
                for (std::size_t w : nb) {
                    sum += pos[w];
                }
                key = sum / static_cast<double>(nb.size());
            }
            keyed.push_back({key, v});
        }
        std::stable_sort(keyed.begin(), keyed.end(),
                         [](const auto& a, const auto& b) { return a.first < b.first; });
        for (std::size_t i = 0; i < L.size(); ++i) {
            L[i] = keyed[i].second;
        }
        renumber(L);
    };
    for (int iter = 0; iter < 4; ++iter) {
        for (std::size_t li = 1; li < layers.size(); ++li) {
            sweep(li, true);
        }
        for (std::size_t li = layers.size(); li-- > 1;) {
            sweep(li - 1, false);
        }
    }

    // ---- 5. coordinates. y per layer; x packed, then relaxed towards the
    // average of neighbours while keeping order and spacing.
    std::vector<double> layerY(layers.size(), 0), layerH(layers.size(), 0);
    double y = 0;
    for (std::size_t li = 0; li < layers.size(); ++li) {
        double h = 0;
        for (std::size_t v : layers[li]) {
            h = std::max(h, vx[v].height);
        }
        layerY[li] = y;
        layerH[li] = h;
        y += h + opt.layerGap;
    }
    auto pack = [&](std::size_t li) {
        // Push right so nodes don't overlap, then pull left so the pushes
        // don't all accumulate on one side.
        auto& L = layers[li];
        for (std::size_t i = 1; i < L.size(); ++i) {
            const double minX = vx[L[i - 1]].x + (vx[L[i - 1]].width + vx[L[i]].width) / 2 + opt.nodeGap;
            vx[L[i]].x = std::max(vx[L[i]].x, minX);
        }
        for (std::size_t i = L.size(); i-- > 1;) {
            const double maxX = vx[L[i]].x - (vx[L[i - 1]].width + vx[L[i]].width) / 2 - opt.nodeGap;
            vx[L[i - 1]].x = std::min(vx[L[i - 1]].x, maxX);
        }
    };
    for (std::size_t li = 0; li < layers.size(); ++li) {
        double x = 0;
        for (std::size_t v : layers[li]) {
            vx[v].x = x + vx[v].width / 2;
            x += vx[v].width + opt.nodeGap;
        }
    }
    for (int iter = 0; iter < 8; ++iter) {
        const bool downward = iter % 2 == 0;
        for (std::size_t k = 0; k < layers.size(); ++k) {
            const std::size_t li = downward ? k : layers.size() - 1 - k;
            for (std::size_t v : layers[li]) {
                const auto& nb = downward ? vx[v].up : vx[v].down;
                if (nb.empty()) {
                    continue;
                }
                double sum = 0;
                for (std::size_t w : nb) {
                    sum += vx[w].x;
                }
                vx[v].x = sum / static_cast<double>(nb.size());
            }
            pack(li);
        }
    }
    double minLeft = 0, maxRight = 0;
    bool first = true;
    for (const auto& v : vx) {
        const double l = v.x - v.width / 2, r = v.x + v.width / 2;
        minLeft = first ? l : std::min(minLeft, l);
        maxRight = first ? r : std::max(maxRight, r);
        first = false;
    }
    for (auto& v : vx) {
        v.x -= minLeft;
    }
    maxRight -= minLeft;

    for (std::size_t v = 0; v < n; ++v) {
        const auto li = static_cast<std::size_t>(vx[v].layer);
        out.nodes[v].x = vx[v].x - vx[v].width / 2;
        out.nodes[v].y = layerY[li];
        out.nodes[v].layer = vx[v].layer;
    }
    for (const auto& L : layers) {
        int order = 0;
        for (std::size_t v : L) {
            if (v < n) {
                out.nodes[v].order = order++;
            }
        }
    }

    // ---- 6. edge routes. Forward edges: bottom of the source, through
    // the dummies, top of the target. Back edges and self loops: out of the
    // source's right side, up a lane right of everything, into the target's
    // right side.
    auto bottomOf = [&](std::size_t v) {
        return Point{vx[v].x, out.nodes[v].y + vx[v].height};
    };
    auto topOf = [&](std::size_t v) { return Point{vx[v].x, out.nodes[v].y}; };
    double lane = maxRight + opt.nodeGap / 2;
    double usedRight = maxRight;
    for (const auto& s : segments) {
        RoutedEdge& re = out.edges[s.edge];
        re.backEdge = s.reversed;
        if (!s.reversed) {
            re.points.push_back(bottomOf(s.chain.front()));
            for (std::size_t k = 1; k + 1 < s.chain.size(); ++k) {
                const std::size_t d = s.chain[k];
                const double dy = layerY[static_cast<std::size_t>(vx[d].layer)];
                re.points.push_back({vx[d].x, dy});
                re.points.push_back({vx[d].x, dy + layerH[static_cast<std::size_t>(vx[d].layer)]});
            }
            re.points.push_back(topOf(s.chain.back()));
        } else {
            // chain runs top (target) to bottom (source).
            const std::size_t src = s.chain.back(), dst = s.chain.front();
            lane += 10;
            usedRight = std::max(usedRight, lane);
            const double sy = out.nodes[src].y + vx[src].height * 0.75;
            const double ty = out.nodes[dst].y + vx[dst].height * 0.25;
            re.points.push_back({out.nodes[src].x + vx[src].width, sy});
            re.points.push_back({lane, sy});
            re.points.push_back({lane, ty});
            re.points.push_back({out.nodes[dst].x + vx[dst].width, ty});
        }
    }
    for (std::size_t i = 0; i < edges.size(); ++i) {
        const auto [a, b] = edges[i];
        if (a < n && a == b) {
            RoutedEdge& re = out.edges[i];
            re.backEdge = true;
            const double right = out.nodes[a].x + vx[a].width;
            const double sy = out.nodes[a].y + vx[a].height * 0.75;
            const double ty = out.nodes[a].y + vx[a].height * 0.25;
            re.points = {{right, sy}, {right + 18, sy}, {right + 18, ty}, {right, ty}};
            usedRight = std::max(usedRight, right + 18);
        }
    }
    out.width = usedRight;
    out.height = layers.empty() ? 0 : layerY.back() + layerH.back();
    return out;
}

} // namespace dasa::core::cfg
