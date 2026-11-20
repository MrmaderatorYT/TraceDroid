// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "core/ForensicSession.hpp"

#include <algorithm>
#include <chrono>

#include "evtx/BinXmlDecoder.hpp"
#include "evtx/SysmonNormalizer.hpp"

namespace td {

namespace {

std::string_view baseName(std::string_view path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void writeRuleJson(JsonWriter& j, const sigma::CompiledRule& rule) {
    j.kv("title", rule.title).kv("id", rule.id).kv("level", static_cast<int>(rule.level));
    j.kv("levelName", sigma::levelName(rule.level)).kv("description", rule.description);
    j.kv("file", rule.sourceFile);
    j.key("tags").beginArray();
    for (const auto& t : rule.tags) j.value(t);
    j.endArray();
}

}  // namespace

/// Clears the cancel flag when a long operation starts so a stale request cannot abort it.
struct ForensicSession::CancelScope {
    explicit CancelScope(std::atomic<bool>& flag) : flag_(flag) { flag_.store(false); }
    ~CancelScope() { flag_.store(false); }
    std::atomic<bool>& flag_;
};

ForensicSession::ForensicSession() = default;
ForensicSession::~ForensicSession() = default;

void ForensicSession::resetQueryLocked() {
    results_.clear();
    hasQuery_ = false;
}

// ---------------------------------------------------------------- evidence

std::string ForensicSession::ingestEvtx(const std::string& path, const ProgressFn& progress) {
    std::unique_lock lock(mutex_);
    CancelScope scope(cancel_);
    const int64_t started = nowMs();

    for (const auto& existing : store_.sources())
        if (existing == path) throw std::runtime_error("this file is already part of the index: " + path);

    evtx::EvtxMmapReader reader(path);
    const size_t rollback = store_.size();
    const size_t sourcesBefore = store_.sources().size();
    uint64_t records = 0, failed = 0, badChunks = 0, usedChunks = 0;
    const size_t chunks = reader.chunkCount();

    try {
        const uint16_t source = store_.addSource(path);
        evtx::SysmonNormalizer normalizer;
        ParsedEvent event;
        std::string error;
        for (size_t c = 0; c < chunks; ++c) {
            if (cancel_.load(std::memory_order_relaxed)) throw Cancelled();
            if ((c & 15) == 0 && progress) progress(kStageParse, c, chunks);

            const auto header = reader.chunkHeader(c);
            if (!header) {
                // Unused (zero-filled) slots are normal in pre-allocated logs; anything else is damage.
                const auto bytes = reader.chunkBytes(c);
                if (std::any_of(bytes.begin(), bytes.begin() + 8, [](uint8_t b) { return b != 0; })) ++badChunks;
                continue;
            }
            ++usedChunks;
            evtx::BinXmlDecoder decoder(reader.chunkBytes(c));
            reader.forEachRecord(c, [&](const evtx::RecordView& rv) {
                ++records;
                if (normalizer.normalize(decoder, rv, event, error)) store_.addEvent(event, source, rv.fileOffset);
                else ++failed;
            });
            reader.releaseChunk(c);  // parsed pages are no longer needed resident
        }
    } catch (...) {
        store_.truncate(rollback);
        if (store_.sources().size() > sourcesBefore) store_.popSource();
        store_.finalize();
        throw;
    }

    if (progress) progress(kStageIndex, 0, 1);
    store_.finalize();
    // New events have not been evaluated: previous alerts and result sets are stale.
    sigma_.clearResults();
    store_.clearSeverity();
    resetQueryLocked();
    if (progress) progress(kStageIndex, 1, 1);

    JsonWriter j;
    j.beginObject();
    j.kv("path", path).kv("events", static_cast<uint64_t>(store_.size() - rollback)).kv("records", records);
    j.kv("failedRecords", failed).kv("chunks", usedChunks).kv("badChunks", badChunks);
    j.kv("dirty", (reader.header().flags & 1u) != 0).kv("headerChecksumValid", reader.header().checksumValid);
    j.kv("elapsedMs", nowMs() - started);
    j.endObject();
    return j.take();
}

void ForensicSession::clearEvents() {
    std::unique_lock lock(mutex_);
    store_.clear();
    sigma_.clearResults();
    graph_ = {};
    geometry_.clear();
    resetQueryLocked();
    const std::lock_guard readers(readersMutex_);
    readers_.clear();
}

void ForensicSession::saveIndex(const std::string& path) {
    std::shared_lock lock(mutex_);
    store_.save(path);
}

bool ForensicSession::loadIndex(const std::string& path) {
    std::unique_lock lock(mutex_);
    sigma_.clearResults();
    graph_ = {};
    geometry_.clear();
    resetQueryLocked();
    {
        const std::lock_guard readers(readersMutex_);
        readers_.clear();
    }
    return store_.load(path);
}

// ---------------------------------------------------------------- Sigma

size_t ForensicSession::loadSigmaRules(const std::string& path) {
    std::unique_lock lock(mutex_);
    return sigma_.loadPath(path);
}

void ForensicSession::clearSigmaRules() {
    std::unique_lock lock(mutex_);
    sigma_.clearRules();
    store_.clearSeverity();
}

std::string ForensicSession::runSigmaScan(const ProgressFn& progress) {
    std::unique_lock lock(mutex_);
    CancelScope scope(cancel_);
    try {
        sigma_.scan(store_, progress, cancel_);
    } catch (...) {
        sigma_.clearResults();
        store_.clearSeverity();
        throw;
    }
    return sigmaSummaryLocked();
}

std::string ForensicSession::sigmaSummaryJson() {
    std::shared_lock lock(mutex_);
    return sigmaSummaryLocked();
}

std::string ForensicSession::sigmaSummaryLocked() const {
    const auto& rules = sigma_.rules();
    const auto& counts = sigma_.ruleHitCounts();
    uint64_t alertEvents = 0;
    uint64_t bySeverity[6] = {};
    for (uint32_t i = 0; i < store_.size(); ++i) {
        const uint8_t s = store_.severity(i);
        if (s) ++alertEvents;
        ++bySeverity[std::min<uint8_t>(s, 5)];
    }

    std::vector<uint32_t> order;
    for (uint32_t r = 0; r < rules.size() && r < counts.size(); ++r)
        if (counts[r] > 0) order.push_back(r);
    std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        if (rules[a].level != rules[b].level) return rules[a].level > rules[b].level;
        if (counts[a] != counts[b]) return counts[a] > counts[b];
        return rules[a].title < rules[b].title;
    });

    JsonWriter j;
    j.beginObject();
    j.kv("rules", static_cast<uint64_t>(rules.size())).kv("hits", static_cast<uint64_t>(sigma_.hits().size()));
    j.kv("alertEvents", alertEvents).kv("scanned", !counts.empty());
    j.key("bySeverity").beginArray();
    for (const uint64_t n : bySeverity) j.value(n);
    j.endArray();
    j.key("ruleHits").beginArray();
    for (const uint32_t r : order) {
        j.beginObject();
        writeRuleJson(j, rules[r]);
        j.kv("count", counts[r]);
        j.endObject();
    }
    j.endArray();
    j.kv("skipped", static_cast<uint64_t>(sigma_.diagnostics().size()));
    j.key("diagnostics").beginArray();
    size_t shown = 0;
    for (const auto& d : sigma_.diagnostics()) {
        if (++shown > 300) break;
        j.beginObject().kv("file", d.sourceFile).kv("title", d.title).kv("message", d.message).endObject();
    }
    j.endArray();
    j.endObject();
    return j.take();
}

// ---------------------------------------------------------------- timeline

uint32_t ForensicSession::query(const QuerySpec& spec) {
    // The scan itself only reads; take the exclusive lock just to publish the result set.
    std::vector<uint32_t> results;
    {
        std::shared_lock lock(mutex_);
        results = store_.query(spec, nullptr);
    }
    std::unique_lock lock(mutex_);
    results_ = std::move(results);
    hasQuery_ = true;
    // Guard against an ingest/clear that slipped in between the two locks.
    const auto total = static_cast<uint32_t>(store_.size());
    std::erase_if(results_, [total](uint32_t i) { return i >= total; });
    return static_cast<uint32_t>(results_.size());
}

std::string ForensicSession::titleOf(uint32_t i) const {
    if (store_.isSysmon(i)) {
        const std::string_view name = evtx::SysmonNormalizer::sysmonEventName(store_.eventId(i));
        if (!name.empty()) return std::string(name);
    }
    std::string_view provider = store_.str(store_.providerId(i));
    if (provider.starts_with("Microsoft-Windows-")) provider.remove_prefix(18);
    return std::string(provider);
}

std::string ForensicSession::summarize(uint32_t i) const {
    const auto& wk = store_.wk();
    auto f = [&](uint32_t key) { return store_.field(i, key); };
    std::string out;
    const uint32_t eid = store_.eventId(i);

    if (store_.isSysmon(i)) {
        switch (eid) {
            case 1: {
                const auto cmd = f(wk.CommandLine);
                out = cmd.empty() ? std::string(f(wk.Image)) : std::string(cmd);
                break;
            }
            case 3:
                out.append(baseName(f(wk.Image))).append(" \xE2\x86\x92 ").append(f(wk.DestinationIp));
                if (const auto port = f(wk.DestinationPort); !port.empty()) out.append(":").append(port);
                if (const auto host = f(wk.DestinationHostname); !host.empty()) out.append(" (").append(host).append(")");
                break;
            case 22:
                out.append(baseName(f(wk.Image))).append(" ? ").append(f(wk.QueryName));
                if (const auto res = f(wk.QueryResults); !res.empty()) out.append(" = ").append(res);
                break;
            case 2: case 11: case 15: case 23: case 26: case 27: case 28: case 29:
                out.append(baseName(f(wk.Image))).append(" \xE2\x86\x92 ").append(f(wk.TargetFilename));
                break;
            case 12: case 13: case 14:
                out.append(baseName(f(wk.Image))).append(" \xE2\x86\x92 ").append(f(wk.TargetObject));
                if (const auto details = f(wk.Details); !details.empty()) out.append(" = ").append(details);
                break;
            case 6: case 7:
                out.append(baseName(f(wk.Image))).append(" \xE2\x86\x90 ").append(f(wk.ImageLoaded));
                break;
            case 8: case 10:
                out.append(baseName(f(wk.SourceImage))).append(" \xE2\x86\x92 ").append(baseName(f(wk.TargetImage)));
                break;
            case 5:
                out = std::string(f(wk.Image));
                break;
            default: break;
        }
    } else if (store_.providerId(i) == wk.securityProvider && eid == 4688) {
        const auto cmd = f(wk.CommandLine);
        out = cmd.empty() ? std::string(f(wk.Image)) : std::string(cmd);
    }
    if (!out.empty()) return out;

    // Generic fallback: the first few non-empty fields as "name=value".
    const auto keys = store_.fieldKeys(i);
    const auto vals = store_.fieldVals(i);
    int shown = 0;
    for (size_t k = 0; k < keys.size() && shown < 4 && out.size() < 360; ++k) {
        const std::string_view name = store_.str(keys[k]), value = store_.str(vals[k]);
        if (value.empty() || name.starts_with("Execution") || name == "SecurityUserID" || name == "Keywords" ||
            name == "Task" || name == "Opcode" || name == "ActivityID")
            continue;
        if (shown++) out.append("  ");
        out.append(name).append("=").append(value.substr(0, 120));
    }
    return out;
}

size_t ForensicSession::fetchPage(uint32_t offset, uint32_t limit, uint8_t* out, size_t capacity) {
    std::shared_lock lock(mutex_);
    const std::vector<uint32_t>& rows = hasQuery_ ? results_ : store_.timeOrder();
    if (capacity < 4) throw std::runtime_error("page buffer too small");
    uint32_t count = 0;
    size_t used = 4;
    ByteWriter row;
    for (uint32_t r = offset; r < rows.size() && count < limit; ++r) {
        const uint32_t i = rows[r];
        row.buffer().clear();
        row.put<uint32_t>(i);
        row.put<uint64_t>(store_.recordId(i));
        row.put<int64_t>(store_.timeMs(i));
        row.put<uint32_t>(store_.eventId(i));
        row.put<uint8_t>(store_.severity(i));
        row.put<uint8_t>(store_.level(i));
        row.put<uint16_t>(static_cast<uint16_t>(std::min<size_t>(sigma_.hitsForEvent(i).size(), 0xFFFF)));
        row.putString(store_.str(store_.channelId(i)), 96);
        row.putString(store_.str(store_.computerId(i)), 64);
        row.putString(titleOf(i), 64);
        row.putString(summarize(i), 400);
        if (used + row.size() > capacity) break;
        std::memcpy(out + used, row.buffer().data(), row.size());
        used += row.size();
        ++count;
    }
    std::memcpy(out, &count, 4);
    return used;
}

std::string ForensicSession::renderXml(uint32_t i) {
    const uint16_t source = store_.source(i);
    try {
        const std::lock_guard readers(readersMutex_);
        auto it = readers_.find(source);
        if (it == readers_.end())
            it = readers_.emplace(source, std::make_unique<evtx::EvtxMmapReader>(store_.sources().at(source))).first;
        const auto record = it->second->recordAtFileOffset(store_.fileOffset(i));
        if (!record) return {};
        evtx::BinXmlDecoder decoder(record->chunk);
        evtx::XmlRenderVisitor xml;
        decoder.decode(record->binXmlOffset, record->binXmlSize, xml);
        return xml.take();
    } catch (const std::exception&) {
        return {};  // evidence file moved or unreadable: the indexed fields are still shown
    }
}

std::string ForensicSession::eventDetailJson(uint32_t i) {
    std::shared_lock lock(mutex_);
    if (i >= store_.size()) throw std::out_of_range("event index out of range");

    const auto hits = sigma_.hitsForEvent(i);
    std::vector<uint32_t> hitKeys;
    for (const auto& h : hits) {
        const auto keys = sigma_.hitKeys(h);
        hitKeys.insert(hitKeys.end(), keys.begin(), keys.end());
    }
    std::sort(hitKeys.begin(), hitKeys.end());
    auto isHit = [&](uint32_t key) { return std::binary_search(hitKeys.begin(), hitKeys.end(), key); };

    JsonWriter j;
    j.beginObject();
    j.kv("index", i).kv("recordId", store_.recordId(i)).kv("timeMs", store_.timeMs(i));
    j.kv("time", formatUnixMs(store_.timeMs(i))).kv("eventId", store_.eventId(i));
    j.kv("title", titleOf(i)).kv("provider", store_.str(store_.providerId(i)));
    j.kv("channel", store_.str(store_.channelId(i))).kv("computer", store_.str(store_.computerId(i)));
    j.kv("level", static_cast<int>(store_.level(i))).kv("severity", static_cast<int>(store_.severity(i)));
    j.kv("source", baseName(store_.sources().at(store_.source(i))));
    j.kv("channelHit", isHit(store_.wk().Channel)).kv("eventIdHit", isHit(store_.wk().EventID));

    j.key("fields").beginArray();
    const auto keys = store_.fieldKeys(i);
    const auto vals = store_.fieldVals(i);
    for (size_t k = 0; k < keys.size(); ++k) {
        j.beginObject().kv("k", store_.str(keys[k])).kv("v", store_.str(vals[k])).kv("hit", isHit(keys[k])).endObject();
    }
    j.endArray();

    j.key("alerts").beginArray();
    for (const auto& h : hits) {
        j.beginObject();
        writeRuleJson(j, sigma_.rules()[h.ruleIndex]);
        j.key("fields").beginArray();
        for (const uint32_t key : sigma_.hitKeys(h)) j.value(store_.str(key));
        j.endArray();
        j.endObject();
    }
    j.endArray();
    j.kv("xml", renderXml(i));
    j.endObject();
    return j.take();
}

// ---------------------------------------------------------------- graph

std::span<const uint8_t> ForensicSession::buildGraph(graph::LayoutMode mode, const graph::BuildOptions& options,
                                                     const ProgressFn& progress) {
    std::unique_lock lock(mutex_);
    CancelScope scope(cancel_);
    if (progress) progress(kStageGraph, 0, 3);
    graph::ProcessGraph g = graph::ProcessTreeBuilder().build(store_, options, &cancel_);
    if (progress) progress(kStageGraph, 1, 3);
    const graph::LayoutMode used = graph::GraphLayoutEngine().layout(g, mode, &cancel_);
    if (progress) progress(kStageGraph, 2, 3);
    std::vector<uint8_t> geometry = graph::GraphLayoutEngine::serialize(g, used);
    // Commit only after everything succeeded so a cancelled rebuild keeps the previous graph intact.
    graph_ = std::move(g);
    geometry_ = std::move(geometry);
    if (progress) progress(kStageGraph, 3, 3);
    return {geometry_.data(), geometry_.size()};
}

std::string ForensicSession::graphNodeDetailJson(uint32_t n) {
    std::shared_lock lock(mutex_);
    if (n >= graph_.nodes.size()) throw std::out_of_range("graph node out of range");
    const graph::GraphNode& node = graph_.nodes[n];
    const auto& wk = store_.wk();
    const bool hasEvent = node.eventIndex < store_.size();
    auto f = [&](uint32_t key) { return hasEvent ? store_.field(node.eventIndex, key) : std::string_view(); };

    JsonWriter j;
    j.beginObject();
    j.kv("id", n).kv("type", static_cast<int>(node.type)).kv("label", node.label);
    j.kv("severity", static_cast<int>(node.severity)).kv("synthetic", (node.flags & graph::kFlagSynthetic) != 0);
    j.kv("terminated", (node.flags & graph::kFlagTerminated) != 0).kv("count", node.count);
    j.kv("eventIndex", hasEvent ? static_cast<int64_t>(node.eventIndex) : int64_t{-1});
    j.kv("time", node.timeMs ? formatUnixMs(node.timeMs) : std::string());
    if (node.endMs != INT64_MAX) j.kv("endTime", formatUnixMs(node.endMs));
    if (hasEvent) j.kv("computer", store_.str(store_.computerId(node.eventIndex)));

    if (node.type == graph::NodeType::Process) {
        j.kv("pid", node.pid).kv("guid", store_.str(node.guidId)).kv("image", store_.str(node.imageId));
        j.kv("commandLine", f(wk.CommandLine)).kv("user", f(wk.User)).kv("hashes", f(wk.Hashes));
        // SHA256 is surfaced separately for quick copy / threat-intel lookup.
        std::string sha256;
        const std::string_view hashes = f(wk.Hashes);
        if (const size_t pos = hashes.find("SHA256="); pos != std::string_view::npos) {
            const size_t end = hashes.find(',', pos);
            sha256 = std::string(hashes.substr(pos + 7, end == std::string_view::npos ? end : end - pos - 7));
        }
        j.kv("sha256", sha256);
        j.kv("parentCommandLine", f(wk.ParentCommandLine));
        size_t processes = 0, connections = 0, queries = 0;
        for (const uint32_t c : node.children) {
            switch (graph_.nodes[c].type) {
                case graph::NodeType::Process: ++processes; break;
                case graph::NodeType::Network: ++connections; break;
                case graph::NodeType::Dns: ++queries; break;
            }
        }
        j.kv("childProcesses", static_cast<uint64_t>(processes)).kv("connections", static_cast<uint64_t>(connections));
        j.kv("dnsQueries", static_cast<uint64_t>(queries));
    } else if (node.type == graph::NodeType::Network) {
        j.kv("destinationIp", f(wk.DestinationIp)).kv("destinationPort", f(wk.DestinationPort));
        j.kv("destinationHostname", f(wk.DestinationHostname)).kv("protocol", f(wk.Protocol));
        j.kv("sourceIp", f(wk.SourceIp)).kv("sourcePort", f(wk.SourcePort)).kv("image", f(wk.Image));
    } else {
        j.kv("queryName", f(wk.QueryName)).kv("queryResults", f(wk.QueryResults)).kv("image", f(wk.Image));
    }

    // Ancestry, nearest parent first.
    j.key("parentChain").beginArray();
    int32_t p = node.parent;
    for (int hops = 0; p >= 0 && hops < 64; ++hops) {
        const graph::GraphNode& a = graph_.nodes[static_cast<size_t>(p)];
        j.beginObject().kv("id", p).kv("label", a.label).kv("image", store_.str(a.imageId));
        j.kv("severity", static_cast<int>(a.severity)).endObject();
        p = a.parent;
    }
    j.endArray();

    // Sigma alerts attributed to this node: its own event plus, for processes, every alerting
    // event carrying the same ProcessGuid.
    j.key("alerts").beginArray();
    size_t emitted = 0;
    auto emit = [&](const sigma::SigmaHit& h) {
        if (emitted++ >= 100) return;
        j.beginObject();
        writeRuleJson(j, sigma_.rules()[h.ruleIndex]);
        j.kv("eventIndex", h.eventIndex).kv("eventId", store_.eventId(h.eventIndex));
        j.kv("time", formatUnixMs(store_.timeMs(h.eventIndex)));
        j.endObject();
    };
    if (node.type == graph::NodeType::Process && node.guidId != 0) {
        for (const auto& h : sigma_.hits()) {
            if (h.eventIndex >= store_.size()) continue;
            if (h.eventIndex == node.eventIndex || store_.fieldId(h.eventIndex, wk.ProcessGuid) == node.guidId ||
                store_.fieldId(h.eventIndex, wk.SourceProcessGuid) == node.guidId)
                emit(h);
        }
    } else if (hasEvent) {
        for (const auto& h : sigma_.hitsForEvent(node.eventIndex)) emit(h);
    }
    j.endArray();
    j.endObject();
    return j.take();
}

// ---------------------------------------------------------------- YARA

size_t ForensicSession::compileYaraRules(const std::string& path) {
    const std::lock_guard lock(yaraMutex_);
    if (!yara_) yara_ = std::make_unique<yara::YaraEngineWrapper>();
    return yara_->compilePath(path);
}

std::string ForensicSession::yaraDiagnosticsJson() {
    const std::lock_guard lock(yaraMutex_);
    JsonWriter j;
    j.beginObject();
    j.kv("available", yara::YaraEngineWrapper::available());
    j.kv("rules", static_cast<uint64_t>(yara_ ? yara_->ruleCount() : 0));
    j.key("errors").beginArray();
    if (yara_)
        for (const auto& e : yara_->errors()) j.value(e);
    j.endArray();
    j.endObject();
    return j.take();
}

std::string ForensicSession::yaraScanFd(int fd, const std::string& displayName, int timeoutSeconds) {
    const std::lock_guard lock(yaraMutex_);
    yara::ScanResult result;
    if (!yara_) result.error = "no YARA rules are loaded";
    else result = yara_->scanFd(fd, timeoutSeconds);

    JsonWriter j;
    j.beginObject();
    j.kv("name", displayName).kv("bytesScanned", result.bytesScanned).kv("timedOut", result.timedOut);
    j.kv("error", result.error);
    j.key("matches").beginArray();
    for (const auto& m : result.matches) {
        j.beginObject();
        j.kv("rule", m.rule).kv("namespace", m.ns).kv("totalStrings", m.totalStringMatches);
        j.key("tags").beginArray();
        for (const auto& t : m.tags) j.value(t);
        j.endArray();
        j.key("meta").beginArray();
        for (const auto& meta : m.metas) {
            j.beginObject().kv("name", meta.name).kv("value", meta.value);
            j.kv("type", std::string_view(&meta.type, 1)).endObject();
        }
        j.endArray();
        j.key("strings").beginArray();
        for (const auto& s : m.strings) {
            j.beginObject().kv("id", s.identifier).kv("offset", s.offset).kv("length", s.length);
            j.kv("contextOffset", s.contextOffset);
            j.kv("context", hexEncode(s.context.data(), s.context.size(), false)).endObject();
        }
        j.endArray();
        j.endObject();
    }
    j.endArray();
    j.endObject();
    return j.take();
}

// ---------------------------------------------------------------- stats

std::string ForensicSession::statsJson() {
    std::shared_lock lock(mutex_);
    uint64_t sysmon = 0, processCreates = 0;
    for (uint32_t i = 0; i < store_.size(); ++i) {
        if (!store_.isSysmon(i)) continue;
        ++sysmon;
        if (store_.eventId(i) == 1) ++processCreates;
    }
    const auto& order = store_.timeOrder();
    JsonWriter j;
    j.beginObject();
    j.kv("events", static_cast<uint64_t>(store_.size())).kv("sysmonEvents", sysmon).kv("processCreates", processCreates);
    j.kv("strings", static_cast<uint64_t>(store_.pool().size())).kv("indexBytes", static_cast<uint64_t>(store_.memoryBytes()));
    j.kv("firstTimeMs", order.empty() ? int64_t{0} : store_.timeMs(order.front()));
    j.kv("lastTimeMs", order.empty() ? int64_t{0} : store_.timeMs(order.back()));
    j.kv("firstTime", order.empty() ? std::string() : formatUnixMs(store_.timeMs(order.front())));
    j.kv("lastTime", order.empty() ? std::string() : formatUnixMs(store_.timeMs(order.back())));
    j.kv("sigmaRules", static_cast<uint64_t>(sigma_.rules().size())).kv("sigmaHits", static_cast<uint64_t>(sigma_.hits().size()));
    j.kv("yaraAvailable", yara::YaraEngineWrapper::available());
    j.key("sources").beginArray();
    for (const auto& s : store_.sources()) j.value(baseName(s));
    j.endArray();
    j.endObject();
    return j.take();
}

}  // namespace td
