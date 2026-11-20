// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "graph/GraphLayoutEngine.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

#include "common/Util.hpp"

namespace td::graph {

LayoutMode GraphLayoutEngine::layout(ProcessGraph& graph, LayoutMode mode, const std::atomic<bool>* cancel) const {
    layoutHierarchical(graph);
    if (mode == LayoutMode::ForceDirected && graph.nodes.size() > 1 && graph.nodes.size() <= kMaxForceNodes) {
        layoutForceDirected(graph, cancel);
        return LayoutMode::ForceDirected;
    }
    return LayoutMode::Hierarchical;
}

// Left-to-right tidy tree: depth selects the column, every leaf takes the next free row and
// each parent is centred on the span of its children. Linear time, no recursion.
void GraphLayoutEngine::layoutHierarchical(ProcessGraph& graph) const {
    auto& nodes = graph.nodes;
    struct Frame {
        uint32_t node;
        uint32_t depth;
        size_t nextChild;
    };
    std::vector<Frame> stack;
    float row = 0;
    for (uint32_t r = 0; r < nodes.size(); ++r) {
        if (nodes[r].parent >= 0) continue;
        stack.push_back({r, 0, 0});
        while (!stack.empty()) {
            Frame& f = stack.back();
            GraphNode& node = nodes[f.node];
            if (f.nextChild < node.children.size()) {
                const uint32_t child = node.children[f.nextChild++];
                stack.push_back({child, f.depth + 1, 0});  // invalidates `f`; not used afterwards
                continue;
            }
            node.x = static_cast<float>(f.depth) * kColumnWidth;
            if (node.children.empty()) {
                node.y = row * kRowHeight;
                row += 1.0f;
            } else {
                node.y = (nodes[node.children.front()].y + nodes[node.children.back()].y) * 0.5f;
            }
            stack.pop_back();
        }
        row += 0.6f;  // visual gap between independent trees
    }
}

// Fruchterman-Reingold with a uniform grid for the repulsive term (each node only interacts
// with nodes in the 3x3 neighbouring cells), seeded from the tree layout so it converges quickly.
void GraphLayoutEngine::layoutForceDirected(ProcessGraph& graph, const std::atomic<bool>* cancel) const {
    auto& nodes = graph.nodes;
    const size_t n = nodes.size();
    const float k = 150.0f;        // ideal edge length
    const float cell = 2.0f * k;   // repulsion cut-off radius
    const int iterations = n > 2500 ? 90 : 160;

    std::vector<float> px(n), py(n), dx(n), dy(n);
    for (size_t i = 0; i < n; ++i) {
        // Compress the tree layout and add a deterministic jitter so no two nodes coincide.
        const uint32_t h = static_cast<uint32_t>(i) * 2654435761u;
        px[i] = nodes[i].x * 0.6f + static_cast<float>(h & 0xFF) * 0.05f;
        py[i] = nodes[i].y * 0.9f + static_cast<float>((h >> 8) & 0xFF) * 0.05f;
    }

    struct CellRef {
        int64_t key;
        uint32_t node;
    };
    std::vector<CellRef> grid(n);
    auto cellKey = [cell](float x, float y) {
        const auto cx = static_cast<int64_t>(std::floor(x / cell));
        const auto cy = static_cast<int64_t>(std::floor(y / cell));
        return (cx << 32) ^ (cy & 0xFFFFFFFFLL);
    };

    float temperature = k * 1.5f;
    const float cooling = temperature / static_cast<float>(iterations + 1);

    for (int iter = 0; iter < iterations; ++iter) {
        if (cancel && cancel->load(std::memory_order_relaxed)) throw Cancelled();
        std::fill(dx.begin(), dx.end(), 0.0f);
        std::fill(dy.begin(), dy.end(), 0.0f);

        for (size_t i = 0; i < n; ++i) grid[i] = {cellKey(px[i], py[i]), static_cast<uint32_t>(i)};
        std::sort(grid.begin(), grid.end(), [](const CellRef& a, const CellRef& b) { return a.key < b.key; });

        // Repulsion.
        for (size_t i = 0; i < n; ++i) {
            const auto cx = static_cast<int64_t>(std::floor(px[i] / cell));
            const auto cy = static_cast<int64_t>(std::floor(py[i] / cell));
            for (int64_t ox = -1; ox <= 1; ++ox) {
                for (int64_t oy = -1; oy <= 1; ++oy) {
                    const int64_t key = ((cx + ox) << 32) ^ ((cy + oy) & 0xFFFFFFFFLL);
                    auto it = std::lower_bound(grid.begin(), grid.end(), key,
                                               [](const CellRef& a, int64_t v) { return a.key < v; });
                    for (; it != grid.end() && it->key == key; ++it) {
                        const size_t j = it->node;
                        if (j == i) continue;
                        float ddx = px[i] - px[j], ddy = py[i] - py[j];
                        float d2 = ddx * ddx + ddy * ddy;
                        if (d2 > cell * cell) continue;
                        if (d2 < 0.01f) {
                            ddx = 0.1f + static_cast<float>(i % 7) * 0.01f;
                            ddy = 0.1f + static_cast<float>(j % 5) * 0.01f;
                            d2 = ddx * ddx + ddy * ddy;
                        }
                        const float force = k * k / d2;  // (k^2 / d) along the unit vector (dd / d)
                        dx[i] += ddx * force;
                        dy[i] += ddy * force;
                    }
                }
            }
        }

        // Attraction along edges.
        for (size_t i = 0; i < n; ++i) {
            if (nodes[i].parent < 0) continue;
            const auto p = static_cast<size_t>(nodes[i].parent);
            const float ddx = px[i] - px[p], ddy = py[i] - py[p];
            const float d = std::sqrt(ddx * ddx + ddy * ddy) + 0.01f;
            // Activity leaves (network / DNS) are pulled closer than child processes.
            const float ideal = nodes[i].type == NodeType::Process ? k : k * 0.6f;
            const float force = d / ideal;  // (d^2 / k) along the unit vector
            dx[i] -= ddx * force;
            dy[i] -= ddy * force;
            dx[p] += ddx * force;
            dy[p] += ddy * force;
        }

        // Displace, limited by the current temperature.
        for (size_t i = 0; i < n; ++i) {
            const float len = std::sqrt(dx[i] * dx[i] + dy[i] * dy[i]);
            if (len < 1e-4f) continue;
            const float step = std::min(len, temperature);
            px[i] += dx[i] / len * step;
            py[i] += dy[i] / len * step;
        }
        temperature -= cooling;
    }

    for (size_t i = 0; i < n; ++i) {
        nodes[i].x = px[i];
        nodes[i].y = py[i];
    }
}

std::vector<uint8_t> GraphLayoutEngine::serialize(const ProcessGraph& graph, LayoutMode usedMode) {
    const auto& nodes = graph.nodes;
    float minX = 0, minY = 0, maxX = 0, maxY = 0;
    if (!nodes.empty()) {
        minX = minY = std::numeric_limits<float>::max();
        maxX = maxY = std::numeric_limits<float>::lowest();
        for (const auto& node : nodes) {
            minX = std::min(minX, node.x);
            minY = std::min(minY, node.y);
            maxX = std::max(maxX, node.x);
            maxY = std::max(maxY, node.y);
        }
    }
    ByteWriter w;
    w.buffer().reserve(32 + nodes.size() * 48);
    w.put<uint32_t>(0x31474454u);  // "TDG1"
    w.put<uint32_t>(static_cast<uint32_t>(nodes.size()));
    w.put<uint32_t>(static_cast<uint32_t>(graph.edgeCount()));
    w.put<uint32_t>((graph.truncated ? 1u : 0u) | (usedMode == LayoutMode::ForceDirected ? 2u : 0u));
    w.put<float>(minX);
    w.put<float>(minY);
    w.put<float>(maxX);
    w.put<float>(maxY);
    for (const auto& node : nodes) {
        w.put<float>(node.x);
        w.put<float>(node.y);
        w.put<uint8_t>(static_cast<uint8_t>(node.type));
        w.put<uint8_t>(node.severity);
        w.put<uint16_t>(node.flags);
        w.put<int32_t>(node.parent);
    }
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].parent < 0) continue;
        w.put<uint32_t>(static_cast<uint32_t>(nodes[i].parent));
        w.put<uint32_t>(i);
    }
    for (const auto& node : nodes) w.putString(node.label, 96);
    return std::move(w.buffer());
}

}  // namespace td::graph
