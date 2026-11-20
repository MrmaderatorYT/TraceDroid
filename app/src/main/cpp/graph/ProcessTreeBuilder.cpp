// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "graph/ProcessTreeBuilder.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <map>
#include <unordered_map>

namespace td::graph {

size_t ProcessGraph::edgeCount() const {
    size_t n = 0;
    for (const auto& node : nodes)
        if (node.parent >= 0) ++n;
    return n;
}

namespace {

// A process that is referenced by pid alone is matched to the most recent creation of that pid;
// pids are recycled, so a creation older than this window is not trusted without a GUID.
constexpr int64_t kPidReuseWindowMs = 24LL * 60 * 60 * 1000;

uint32_t parsePid(std::string_view s) {
    s = trim(s);
    uint32_t v = 0;
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
        base = 16;
    }
    std::from_chars(s.data(), s.data() + s.size(), v, base);
    return v;
}

std::string_view baseName(std::string_view path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

bool isNullGuid(std::string_view g) {
    return g.empty() || g.find_first_not_of("{}-0") == std::string_view::npos;
}

class Builder {
public:
    Builder(const EventStore& store, const BuildOptions& opts) : s_(store), wk_(store.wk()), opts_(opts) {}

    ProcessGraph run(const std::atomic<bool>* cancel) {
        size_t n = 0;
        for (const uint32_t i : s_.timeOrder()) {
            if (cancel && (++n & 0x3FFF) == 0 && cancel->load(std::memory_order_relaxed)) throw Cancelled();
            const uint32_t eid = s_.eventId(i);
            if (s_.isSysmon(i)) {
                switch (eid) {
                    case 1: onProcessCreate(i); break;
                    case 5: onProcessTerminate(i); break;
                    case 3:
                        if (opts_.includeNetwork) onNetwork(i);
                        break;
                    case 22:
                        if (opts_.includeDns) onDns(i);
                        break;
                    default: break;
                }
            } else if (s_.providerId(i) == wk_.securityProvider) {
                if (eid == 4688) onProcessCreate(i);
                else if (eid == 4689) onProcessTerminate(i);
            }
        }
        attributeAlerts(cancel);
        return compact();
    }

private:
    uint32_t guidOf(uint32_t i, uint32_t key) const {
        const uint32_t id = s_.fieldId(i, key);
        return id != 0 && !isNullGuid(s_.str(id)) ? id : 0;
    }

    uint32_t newProcess(uint32_t guidId, uint32_t pid, uint32_t imageId, int64_t timeMs, bool synthetic) {
        GraphNode node;
        node.type = NodeType::Process;
        node.guidId = guidId;
        node.pid = pid;
        node.imageId = imageId;
        node.timeMs = timeMs;
        if (synthetic) node.flags |= kFlagSynthetic;
        const auto idx = static_cast<uint32_t>(nodes_.size());
        nodes_.push_back(std::move(node));
        if (guidId) byGuid_[guidId] = idx;
        if (pid) byPid_[pid].push_back(idx);
        return idx;
    }

    // Latest process with this pid that was alive at `timeMs`.
    int findByPid(uint32_t pid, int64_t timeMs) const {
        const auto it = byPid_.find(pid);
        if (it == byPid_.end()) return -1;
        for (auto r = it->second.rbegin(); r != it->second.rend(); ++r) {
            const GraphNode& node = nodes_[*r];
            if (node.timeMs > timeMs) continue;
            if (node.endMs < timeMs) return -1;  // the most recent holder already exited: pid was recycled
            if (timeMs - node.timeMs > kPidReuseWindowMs && !(node.flags & kFlagSynthetic)) return -1;
            return static_cast<int>(*r);
        }
        return -1;
    }

    uint32_t resolveProcess(uint32_t guidId, uint32_t pid, uint32_t imageId, int64_t timeMs) {
        if (guidId) {
            if (const auto it = byGuid_.find(guidId); it != byGuid_.end()) return it->second;
            return newProcess(guidId, pid, imageId, timeMs, true);
        }
        if (const int found = findByPid(pid, timeMs); found >= 0) return static_cast<uint32_t>(found);
        return newProcess(0, pid, imageId, timeMs, true);
    }

    void setParent(uint32_t child, uint32_t parent) {
        if (child == parent) return;
        // Corrupt or adversarial GUID chains must not create cycles.
        uint32_t cur = parent;
        for (int hops = 0; hops < 4096; ++hops) {
            if (cur == child) return;
            if (nodes_[cur].parent < 0) break;
            cur = static_cast<uint32_t>(nodes_[cur].parent);
        }
        nodes_[child].parent = static_cast<int32_t>(parent);
    }

    void onProcessCreate(uint32_t i) {
        const int64_t t = s_.timeMs(i);
        const uint32_t guid = guidOf(i, wk_.ProcessGuid);
        const uint32_t pid = parsePid(s_.field(i, wk_.ProcessId));
        const uint32_t image = s_.fieldId(i, wk_.Image);

        uint32_t node;
        const auto known = guid ? byGuid_.find(guid) : byGuid_.end();
        if (known != byGuid_.end()) {
            // Referenced earlier (as a parent or by network activity); now we have the real record.
            node = known->second;
            GraphNode& g = nodes_[node];
            g.flags &= static_cast<uint16_t>(~kFlagSynthetic);
            g.timeMs = t;
            if (image) g.imageId = image;
            if (!g.pid && pid) {
                g.pid = pid;
                byPid_[pid].push_back(node);
            }
        } else {
            node = newProcess(guid, pid, image, t, false);
        }
        nodes_[node].eventIndex = i;
        nodes_[node].severity = std::max(nodes_[node].severity, s_.severity(i));

        const uint32_t parentGuid = guidOf(i, wk_.ParentProcessGuid);
        const uint32_t parentPid = parsePid(s_.field(i, wk_.ParentProcessId));
        if (!parentGuid && !parentPid) return;
        const uint32_t parent = resolveProcess(parentGuid, parentPid, s_.fieldId(i, wk_.ParentImage), t);
        setParent(node, parent);
    }

    void onProcessTerminate(uint32_t i) {
        const uint32_t guid = guidOf(i, wk_.ProcessGuid);
        int node = -1;
        if (guid) {
            if (const auto it = byGuid_.find(guid); it != byGuid_.end()) node = static_cast<int>(it->second);
        } else {
            node = findByPid(parsePid(s_.field(i, wk_.ProcessId)), s_.timeMs(i));
        }
        if (node < 0) return;
        nodes_[static_cast<size_t>(node)].endMs = s_.timeMs(i);
        nodes_[static_cast<size_t>(node)].flags |= kFlagTerminated;
    }

    void attach(uint32_t i, NodeType type, uint32_t targetId, uint32_t discriminator, std::string label) {
        const uint32_t proc = resolveProcess(guidOf(i, wk_.ProcessGuid), parsePid(s_.field(i, wk_.ProcessId)),
                                             s_.fieldId(i, wk_.Image), s_.timeMs(i));
        const std::array<uint32_t, 4> key{proc, static_cast<uint32_t>(type), targetId, discriminator};
        if (const auto it = activity_.find(key); it != activity_.end()) {
            GraphNode& g = nodes_[it->second];
            ++g.count;
            g.severity = std::max(g.severity, s_.severity(i));
            return;
        }
        GraphNode node;
        node.type = type;
        node.parent = static_cast<int32_t>(proc);
        node.eventIndex = i;
        node.imageId = targetId;
        node.timeMs = s_.timeMs(i);
        node.severity = s_.severity(i);
        node.label = std::move(label);
        activity_.emplace(key, static_cast<uint32_t>(nodes_.size()));
        nodes_.push_back(std::move(node));
    }

    void onNetwork(uint32_t i) {
        const uint32_t ip = s_.fieldId(i, wk_.DestinationIp);
        const uint32_t port = s_.fieldId(i, wk_.DestinationPort);
        if (!ip) return;
        std::string label(s_.str(ip));
        if (label.find(':') != std::string::npos) label = "[" + label + "]";  // IPv6
        if (port) {
            label.push_back(':');
            label.append(s_.str(port));
        }
        attach(i, NodeType::Network, ip, port, std::move(label));
    }

    void onDns(uint32_t i) {
        const uint32_t query = s_.fieldId(i, wk_.QueryName);
        if (!query) return;
        attach(i, NodeType::Dns, query, 0, std::string(s_.str(query)));
    }

    // Any alerting Sysmon event raises the severity of the process it belongs to, not just
    // the ProcessCreate record (e.g. a registry or file alert raised by that process later).
    void attributeAlerts(const std::atomic<bool>* cancel) {
        const auto total = static_cast<uint32_t>(s_.size());
        for (uint32_t i = 0; i < total; ++i) {
            if (cancel && (i & 0xFFFF) == 0 && cancel->load(std::memory_order_relaxed)) throw Cancelled();
            const uint8_t sev = s_.severity(i);
            if (!sev || !s_.isSysmon(i)) continue;
            uint32_t guid = guidOf(i, wk_.ProcessGuid);
            if (!guid) guid = guidOf(i, wk_.SourceProcessGuid);  // CreateRemoteThread / ProcessAccess
            if (!guid) continue;
            if (const auto it = byGuid_.find(guid); it != byGuid_.end())
                nodes_[it->second].severity = std::max(nodes_[it->second].severity, sev);
        }
    }

    ProcessGraph compact() {
        const auto n = static_cast<uint32_t>(nodes_.size());
        std::vector<std::vector<uint32_t>> children(n);
        std::vector<uint32_t> roots;
        for (uint32_t i = 0; i < n; ++i) {
            if (nodes_[i].parent >= 0) children[static_cast<size_t>(nodes_[i].parent)].push_back(i);
            else roots.push_back(i);
        }
        auto byKindThenTime = [this](uint32_t a, uint32_t b) {
            const GraphNode &x = nodes_[a], &y = nodes_[b];
            if (x.type != y.type) return x.type < y.type;
            if (x.timeMs != y.timeMs) return x.timeMs < y.timeMs;
            return a < b;
        };
        for (auto& c : children) std::sort(c.begin(), c.end(), byKindThenTime);

        // Highest severity anywhere in each subtree (iterative post-order).
        std::vector<uint8_t> subtreeMax(n, 0);
        std::vector<uint32_t> order;
        order.reserve(n);
        {
            std::vector<uint32_t> stack(roots.rbegin(), roots.rend());
            while (!stack.empty()) {
                const uint32_t v = stack.back();
                stack.pop_back();
                order.push_back(v);
                for (auto it = children[v].rbegin(); it != children[v].rend(); ++it) stack.push_back(*it);
            }
            for (auto it = order.rbegin(); it != order.rend(); ++it) {
                uint8_t m = nodes_[*it].severity;
                for (const uint32_t c : children[*it]) m = std::max(m, subtreeMax[c]);
                subtreeMax[*it] = m;
            }
        }

        // Most severe trees first, then chronological.
        std::stable_sort(roots.begin(), roots.end(), [&](uint32_t a, uint32_t b) {
            if (subtreeMax[a] != subtreeMax[b]) return subtreeMax[a] > subtreeMax[b];
            return nodes_[a].timeMs < nodes_[b].timeMs;
        });

        const auto minSev = static_cast<uint8_t>(std::clamp(opts_.minSeverity, 0, 5));
        ProcessGraph graph;
        std::vector<int32_t> remap(n, -1);
        // Breadth-first so that a parent is always emitted before its children and truncation
        // removes the deepest, least relevant nodes first.
        struct Item {
            uint32_t node;
            bool underAlert;  // an ancestor carries an alert: keep the whole descendant branch
        };
        std::vector<Item> queue;
        queue.reserve(n);
        for (const uint32_t r : roots)
            if (subtreeMax[r] >= minSev) queue.push_back({r, false});
        for (size_t head = 0; head < queue.size(); ++head) {
            const Item item = queue[head];
            if (graph.nodes.size() >= opts_.maxNodes) {
                graph.truncated = true;
                break;
            }
            GraphNode node = std::move(nodes_[item.node]);
            const bool alerting = item.underAlert || (minSev > 0 && node.severity >= minSev);
            remap[item.node] = static_cast<int32_t>(graph.nodes.size());
            node.parent = node.parent >= 0 ? remap[static_cast<size_t>(node.parent)] : -1;
            if (node.parent < 0) node.flags |= kFlagRoot;
            if (node.type == NodeType::Process) {
                const std::string_view image = s_.str(node.imageId);
                node.label = image.empty() ? std::string("<unknown>") : std::string(baseName(image));
                if (node.pid) node.label += " (" + std::to_string(node.pid) + ")";
            } else if (node.count > 1) {
                node.label += " \xC3\x97" + std::to_string(node.count);  // "×N"
            }
            graph.nodes.push_back(std::move(node));
            for (const uint32_t c : children[item.node])
                if (minSev == 0 || alerting || subtreeMax[c] >= minSev) queue.push_back({c, alerting});
        }
        for (uint32_t i = 0; i < graph.nodes.size(); ++i)
            if (graph.nodes[i].parent >= 0) graph.nodes[static_cast<size_t>(graph.nodes[i].parent)].children.push_back(i);
        return graph;
    }

    const EventStore& s_;
    const EventStore::WellKnown& wk_;
    const BuildOptions& opts_;
    std::vector<GraphNode> nodes_;
    std::unordered_map<uint32_t, uint32_t> byGuid_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> byPid_;
    std::map<std::array<uint32_t, 4>, uint32_t> activity_;
};

}  // namespace

ProcessGraph ProcessTreeBuilder::build(const EventStore& store, const BuildOptions& options,
                                       const std::atomic<bool>* cancel) const {
    return Builder(store, options).run(cancel);
}

}  // namespace td::graph
