// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// One forensic case opened in the native engine. The JNI layer holds a pointer to this object
// as an opaque `long` handle; destroying it releases every mapping, index and rule set (RAII).
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/Util.hpp"
#include "evtx/EvtxMmapReader.hpp"
#include "graph/GraphLayoutEngine.hpp"
#include "graph/ProcessTreeBuilder.hpp"
#include "sigma/SigmaEngine.hpp"
#include "store/EventStore.hpp"
#include "yara/YaraEngineWrapper.hpp"

namespace td {

class ForensicSession {
public:
    ForensicSession();
    ~ForensicSession();
    ForensicSession(const ForensicSession&) = delete;
    ForensicSession& operator=(const ForensicSession&) = delete;

    /// Requests cancellation of the operation currently running on another thread.
    void cancel() { cancel_.store(true); }

    // ---- evidence ----
    /// Parses an .evtx file into the index. Returns a JSON report
    /// {"path","events","records","failedRecords","chunks","badChunks","dirty","elapsedMs"}.
    std::string ingestEvtx(const std::string& path, const ProgressFn& progress);
    void clearEvents();
    void saveIndex(const std::string& path);
    bool loadIndex(const std::string& path);

    // ---- Sigma ----
    size_t loadSigmaRules(const std::string& path);
    void clearSigmaRules();
    /// Runs the batch scan and returns the same JSON as sigmaSummaryJson().
    std::string runSigmaScan(const ProgressFn& progress);
    std::string sigmaSummaryJson();

    // ---- timeline ----
    /// Runs a filter and stores the result set for paging. Returns the number of matching events.
    uint32_t query(const QuerySpec& spec);
    /// Serialises rows [offset, offset+limit) of the current result set into `out`:
    ///   u32 rowCount, then per row: u32 eventIndex, u64 recordId, i64 timeMs, u32 eventId,
    ///   u8 severity, u8 level, u16 alertCount, and four strings (u16 length + UTF-8):
    ///   channel, computer, title, summary.
    /// Fewer rows than requested are written when `capacity` is too small. Returns bytes written.
    size_t fetchPage(uint32_t offset, uint32_t limit, uint8_t* out, size_t capacity);
    std::string eventDetailJson(uint32_t eventIndex);

    // ---- graph ----
    /// Builds and lays out the process/network graph. The returned geometry stays valid until the
    /// next buildGraph call or destruction of the session.
    std::span<const uint8_t> buildGraph(graph::LayoutMode mode, const graph::BuildOptions& options,
                                        const ProgressFn& progress);
    std::string graphNodeDetailJson(uint32_t nodeIndex);

    // ---- YARA ----
    size_t compileYaraRules(const std::string& path);
    std::string yaraDiagnosticsJson();
    /// Scans the artifact behind `fd`; the descriptor is owned by the caller.
    std::string yaraScanFd(int fd, const std::string& displayName, int timeoutSeconds);

    std::string statsJson();

private:
    struct CancelScope;
    void resetQueryLocked();
    std::string sigmaSummaryLocked() const;
    std::string summarize(uint32_t eventIndex) const;
    std::string titleOf(uint32_t eventIndex) const;
    std::string renderXml(uint32_t eventIndex);

    mutable std::shared_mutex mutex_;
    std::atomic<bool> cancel_{false};

    EventStore store_;
    sigma::SigmaEngine sigma_;
    std::mutex yaraMutex_;
    std::unique_ptr<yara::YaraEngineWrapper> yara_;

    std::vector<uint32_t> results_;
    bool hasQuery_ = false;

    graph::ProcessGraph graph_;
    std::vector<uint8_t> geometry_;

    std::mutex readersMutex_;
    std::unordered_map<uint16_t, std::unique_ptr<evtx::EvtxMmapReader>> readers_;
};

}  // namespace td
