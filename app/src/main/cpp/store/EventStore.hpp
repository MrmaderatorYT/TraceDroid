// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Embedded columnar event index. Every string (field names and values) is interned once
// in an arena-backed pool; an event is a row of fixed-width columns plus a slice of
// (key id, value id) pairs. Filtering evaluates a predicate once per *distinct* string
// and then scans integer columns, which is what keeps keyword/regex queries sub-second
// on multi-million event datasets.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "common/Util.hpp"

namespace td {

class StringPool {
public:
    StringPool();
    uint32_t intern(std::string_view s);
    std::optional<uint32_t> find(std::string_view s) const;
    std::string_view get(uint32_t id) const { return entries_[id]; }
    size_t size() const { return entries_.size(); }
    size_t bytes() const { return bytes_; }
    void clear();

private:
    const char* store(std::string_view s);
    static constexpr size_t kBlockSize = 1 << 20;
    std::vector<std::unique_ptr<char[]>> blocks_;
    size_t blockUsed_ = kBlockSize;
    size_t bytes_ = 0;
    std::vector<std::string_view> entries_;
    std::unordered_map<std::string_view, uint32_t> index_;
};

/// Normalised event as produced by the EVTX pipeline, before interning.
struct ParsedEvent {
    uint64_t recordId = 0;
    int64_t timeMs = 0;
    uint32_t eventId = 0;
    uint8_t level = 0;
    std::string provider;
    std::string channel;
    std::string computer;
    std::vector<std::pair<std::string, std::string>> fields;

    void clear() {
        recordId = 0;
        timeMs = 0;
        eventId = 0;
        level = 0;
        provider.clear();
        channel.clear();
        computer.clear();
        fields.clear();
    }
    const std::string* find(std::string_view key) const {
        for (const auto& f : fields)
            if (f.first == key) return &f.second;
        return nullptr;
    }
};

struct QuerySpec {
    std::string text;       // keyword (case-insensitive substring) or regular expression
    bool regex = false;
    int eventId = -1;       // -1 = any
    int minSeverity = 0;    // 0 = any, 1..5 = informational..critical Sigma level
    int64_t fromMs = INT64_MIN;
    int64_t toMs = INT64_MAX;
};

class EventStore {
public:
    /// Pool ids of field names the engine itself needs; resolved once so hot paths compare integers.
    struct WellKnown {
        uint32_t EventID, Channel, Provider_Name, Computer;
        uint32_t UtcTime, ProcessGuid, ProcessId, Image, CommandLine, Hashes, User;
        uint32_t ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine;
        uint32_t SourceIp, SourcePort, DestinationIp, DestinationPort, DestinationHostname, Protocol;
        uint32_t QueryName, QueryResults, TargetFilename, TargetObject, Details, ImageLoaded;
        uint32_t SourceImage, TargetImage, SourceProcessGuid, TargetProcessGuid;
        uint32_t sysmonProvider, securityProvider;
    };
    static constexpr uint32_t kNoString = 0;  // pool id 0 is always the empty string

    EventStore();

    uint16_t addSource(std::string path);
    const std::vector<std::string>& sources() const { return sources_; }
    /// Forgets the most recently added source (used when its ingest is rolled back).
    void popSource() {
        if (!sources_.empty()) sources_.pop_back();
    }
    uint32_t addEvent(const ParsedEvent& ev, uint16_t source, uint64_t fileOffset);
    /// Rebuilds the time-ordered index. Must be called after a batch of addEvent calls.
    void finalize();
    void clear();
    /// Drops every event at index >= count (rolls back a failed or cancelled ingest). Call finalize() afterwards.
    void truncate(size_t count);

    size_t size() const { return recordId_.size(); }
    uint64_t recordId(uint32_t i) const { return recordId_[i]; }
    int64_t timeMs(uint32_t i) const { return timeMs_[i]; }
    uint32_t eventId(uint32_t i) const { return eventId_[i]; }
    uint8_t level(uint32_t i) const { return level_[i]; }
    uint32_t providerId(uint32_t i) const { return provider_[i]; }
    uint32_t channelId(uint32_t i) const { return channel_[i]; }
    uint32_t computerId(uint32_t i) const { return computer_[i]; }
    uint16_t source(uint32_t i) const { return source_[i]; }
    uint64_t fileOffset(uint32_t i) const { return fileOffset_[i]; }
    bool isSysmon(uint32_t i) const { return provider_[i] == wk_.sysmonProvider; }

    std::span<const uint32_t> fieldKeys(uint32_t i) const {
        return {keys_.data() + fieldStart_[i], fieldStart_[i + 1] - fieldStart_[i]};
    }
    std::span<const uint32_t> fieldVals(uint32_t i) const {
        return {vals_.data() + fieldStart_[i], fieldStart_[i + 1] - fieldStart_[i]};
    }
    /// Pool id of the value of field `key`, or kNoString when the field is absent.
    uint32_t fieldId(uint32_t i, uint32_t key) const {
        const uint32_t b = fieldStart_[i], e = fieldStart_[i + 1];
        for (uint32_t k = b; k < e; ++k)
            if (keys_[k] == key) return vals_[k];
        return kNoString;
    }
    bool hasField(uint32_t i, uint32_t key) const {
        const uint32_t b = fieldStart_[i], e = fieldStart_[i + 1];
        for (uint32_t k = b; k < e; ++k)
            if (keys_[k] == key) return true;
        return false;
    }
    std::string_view field(uint32_t i, uint32_t key) const { return pool_.get(fieldId(i, key)); }
    std::string_view str(uint32_t id) const { return pool_.get(id); }

    uint8_t severity(uint32_t i) const { return severity_[i]; }
    void raiseSeverity(uint32_t i, uint8_t s) {
        if (s > severity_[i]) severity_[i] = s;
    }
    void clearSeverity();

    const std::vector<uint32_t>& timeOrder() const { return order_; }
    const WellKnown& wk() const { return wk_; }
    StringPool& pool() { return pool_; }
    const StringPool& pool() const { return pool_; }

    /// Returns matching event indices in chronological order. Throws std::runtime_error on a bad regex.
    std::vector<uint32_t> query(const QuerySpec& spec, const std::atomic<bool>* cancel = nullptr) const;

    /// Binary snapshot of the whole index (little-endian, versioned). Sigma severities are not persisted.
    void save(const std::string& path) const;
    /// Returns false when the file is missing or is not a compatible snapshot.
    bool load(const std::string& path);

    size_t memoryBytes() const;

private:
    void resolveWellKnown();

    StringPool pool_;
    WellKnown wk_{};
    std::vector<std::string> sources_;

    std::vector<uint64_t> recordId_;
    std::vector<int64_t> timeMs_;
    std::vector<uint64_t> fileOffset_;
    std::vector<uint32_t> eventId_;
    std::vector<uint32_t> provider_;
    std::vector<uint32_t> channel_;
    std::vector<uint32_t> computer_;
    std::vector<uint32_t> fieldStart_;  // size() + 1 entries
    std::vector<uint16_t> source_;
    std::vector<uint8_t> level_;
    std::vector<uint8_t> severity_;
    std::vector<uint32_t> keys_;
    std::vector<uint32_t> vals_;
    std::vector<uint32_t> order_;
};

}  // namespace td
