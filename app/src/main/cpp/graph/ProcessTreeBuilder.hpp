// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Rebuilds process execution trees from Sysmon ProcessCreate (EID 1) and Security 4688 events
// and hangs NetworkConnect (EID 3) / DnsQuery (EID 22) activity off the owning process.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "store/EventStore.hpp"

namespace td::graph {

enum class NodeType : uint8_t { Process = 0, Network = 1, Dns = 2 };

enum NodeFlags : uint16_t {
    kFlagSynthetic = 1,   // process known only by reference (no ProcessCreate record in the dataset)
    kFlagTerminated = 2,  // a ProcessTerminate record was seen
    kFlagRoot = 4,
};

struct GraphNode {
    NodeType type = NodeType::Process;
    uint8_t severity = 0;  // highest Sigma level attributed to this node (0 = none)
    uint16_t flags = 0;
    int32_t parent = -1;
    uint32_t eventIndex = UINT32_MAX;  // creating / first event in the store, if any
    uint32_t count = 1;                // aggregated events (connections or queries)
    uint32_t pid = 0;
    uint32_t guidId = 0;               // pool id of ProcessGuid (0 = unknown)
    uint32_t imageId = 0;              // pool id of the image path (process) or the target text (net/dns)
    int64_t timeMs = 0;
    int64_t endMs = INT64_MAX;
    std::string label;
    std::vector<uint32_t> children;
    float x = 0, y = 0;
};

struct ProcessGraph {
    std::vector<GraphNode> nodes;
    bool truncated = false;  // node budget exceeded; lowest-priority branches were dropped
    size_t edgeCount() const;
};

struct BuildOptions {
    int minSeverity = 0;        // >0: keep only branches that contain (or descend from) an alert of this level
    bool includeNetwork = true;
    bool includeDns = true;
    size_t maxNodes = 20000;
};

class ProcessTreeBuilder {
public:
    ProcessGraph build(const EventStore& store, const BuildOptions& options, const std::atomic<bool>* cancel = nullptr) const;
};

}  // namespace td::graph
