// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#pragma once

#include <atomic>
#include <cstdint>
#include <vector>

#include "graph/ProcessTreeBuilder.hpp"

namespace td::graph {

enum class LayoutMode : int { Hierarchical = 0, ForceDirected = 1 };

/// Computes node coordinates natively and serialises the geometry for the Java renderer.
class GraphLayoutEngine {
public:
    static constexpr float kColumnWidth = 300.0f;
    static constexpr float kRowHeight = 64.0f;
    /// Above this size the force simulation is skipped in favour of the O(n) tree layout.
    static constexpr size_t kMaxForceNodes = 6000;

    /// Returns the mode actually used (ForceDirected falls back to Hierarchical on very large graphs).
    LayoutMode layout(ProcessGraph& graph, LayoutMode mode, const std::atomic<bool>* cancel = nullptr) const;

    /// Geometry buffer (little-endian):
    ///   header  : u32 magic 'TDG1', u32 nodeCount, u32 edgeCount, u32 flags (bit0 truncated, bit1 force layout),
    ///             f32 minX, f32 minY, f32 maxX, f32 maxY
    ///   nodes   : nodeCount * { f32 x, f32 y, u8 type, u8 severity, u16 flags, i32 parent }
    ///   edges   : edgeCount * { u32 source, u32 target }
    ///   labels  : nodeCount * { u16 byteLength, UTF-8 bytes }
    static std::vector<uint8_t> serialize(const ProcessGraph& graph, LayoutMode usedMode);

private:
    void layoutHierarchical(ProcessGraph& graph) const;
    void layoutForceDirected(ProcessGraph& graph, const std::atomic<bool>* cancel) const;
};

}  // namespace td::graph
