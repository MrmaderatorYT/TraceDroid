// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "store/EventStore.hpp"

#include <algorithm>
#include <cstdio>
#include <regex>

namespace td {

// ---------------------------------------------------------------- StringPool

StringPool::StringPool() { clear(); }

void StringPool::clear() {
    blocks_.clear();
    entries_.clear();
    index_.clear();
    blockUsed_ = kBlockSize;
    bytes_ = 0;
    intern("");  // id 0
}

const char* StringPool::store(std::string_view s) {
    if (s.size() >= kBlockSize / 4) {  // oversized strings get a dedicated block
        auto block = std::make_unique<char[]>(s.size() + 1);
        std::memcpy(block.get(), s.data(), s.size());
        const char* p = block.get();
        // Keep the current partially-filled block last so small strings continue to use it.
        if (blocks_.empty()) {
            blocks_.push_back(std::move(block));
            blockUsed_ = kBlockSize;
        } else {
            blocks_.insert(blocks_.end() - 1, std::move(block));
        }
        return p;
    }
    if (blocks_.empty() || blockUsed_ + s.size() > kBlockSize) {
        blocks_.push_back(std::make_unique<char[]>(kBlockSize));
        blockUsed_ = 0;
    }
    char* p = blocks_.back().get() + blockUsed_;
    if (!s.empty()) std::memcpy(p, s.data(), s.size());
    blockUsed_ += s.size();
    return p;
}

uint32_t StringPool::intern(std::string_view s) {
    if (const auto it = index_.find(s); it != index_.end()) return it->second;
    const std::string_view stored(store(s), s.size());
    const auto id = static_cast<uint32_t>(entries_.size());
    entries_.push_back(stored);
    index_.emplace(stored, id);
    bytes_ += s.size();
    return id;
}

std::optional<uint32_t> StringPool::find(std::string_view s) const {
    if (const auto it = index_.find(s); it != index_.end()) return it->second;
    return std::nullopt;
}

// ---------------------------------------------------------------- EventStore

EventStore::EventStore() {
    fieldStart_.push_back(0);
    resolveWellKnown();
}

void EventStore::resolveWellKnown() {
#define TD_WK(name) wk_.name = pool_.intern(#name)
    TD_WK(EventID); TD_WK(Channel); TD_WK(Provider_Name); TD_WK(Computer);
    TD_WK(UtcTime); TD_WK(ProcessGuid); TD_WK(ProcessId); TD_WK(Image); TD_WK(CommandLine); TD_WK(Hashes); TD_WK(User);
    TD_WK(ParentProcessGuid); TD_WK(ParentProcessId); TD_WK(ParentImage); TD_WK(ParentCommandLine);
    TD_WK(SourceIp); TD_WK(SourcePort); TD_WK(DestinationIp); TD_WK(DestinationPort); TD_WK(DestinationHostname);
    TD_WK(Protocol); TD_WK(QueryName); TD_WK(QueryResults); TD_WK(TargetFilename); TD_WK(TargetObject);
    TD_WK(Details); TD_WK(ImageLoaded); TD_WK(SourceImage); TD_WK(TargetImage); TD_WK(SourceProcessGuid);
    TD_WK(TargetProcessGuid);
#undef TD_WK
    wk_.sysmonProvider = pool_.intern("Microsoft-Windows-Sysmon");
    wk_.securityProvider = pool_.intern("Microsoft-Windows-Security-Auditing");
}

void EventStore::clear() {
    pool_.clear();
    sources_.clear();
    recordId_.clear();
    timeMs_.clear();
    fileOffset_.clear();
    eventId_.clear();
    provider_.clear();
    channel_.clear();
    computer_.clear();
    fieldStart_.assign(1, 0);
    source_.clear();
    level_.clear();
    severity_.clear();
    keys_.clear();
    vals_.clear();
    order_.clear();
    resolveWellKnown();
}

void EventStore::truncate(size_t count) {
    if (count >= size()) return;
    const uint32_t fieldEnd = fieldStart_[count];
    recordId_.resize(count);
    timeMs_.resize(count);
    fileOffset_.resize(count);
    eventId_.resize(count);
    provider_.resize(count);
    channel_.resize(count);
    computer_.resize(count);
    source_.resize(count);
    level_.resize(count);
    severity_.resize(count);
    fieldStart_.resize(count + 1);
    keys_.resize(fieldEnd);
    vals_.resize(fieldEnd);
    order_.clear();
}

uint16_t EventStore::addSource(std::string path) {
    for (size_t i = 0; i < sources_.size(); ++i)
        if (sources_[i] == path) return static_cast<uint16_t>(i);
    if (sources_.size() >= 0xFFFF) throw std::runtime_error("too many evidence files in one session");
    sources_.push_back(std::move(path));
    return static_cast<uint16_t>(sources_.size() - 1);
}

uint32_t EventStore::addEvent(const ParsedEvent& ev, uint16_t source, uint64_t fileOffset) {
    if (recordId_.size() >= 0xFFFFFFF0u) throw std::runtime_error("event index is full");
    const auto idx = static_cast<uint32_t>(recordId_.size());
    recordId_.push_back(ev.recordId);
    timeMs_.push_back(ev.timeMs);
    fileOffset_.push_back(fileOffset);
    eventId_.push_back(ev.eventId);
    provider_.push_back(pool_.intern(ev.provider));
    channel_.push_back(pool_.intern(ev.channel));
    computer_.push_back(pool_.intern(ev.computer));
    source_.push_back(source);
    level_.push_back(ev.level);
    severity_.push_back(0);
    for (const auto& [k, v] : ev.fields) {
        keys_.push_back(pool_.intern(k));
        vals_.push_back(pool_.intern(v));
    }
    fieldStart_.push_back(static_cast<uint32_t>(keys_.size()));
    return idx;
}

void EventStore::finalize() {
    order_.resize(size());
    for (uint32_t i = 0; i < order_.size(); ++i) order_[i] = i;
    std::stable_sort(order_.begin(), order_.end(), [this](uint32_t a, uint32_t b) {
        if (timeMs_[a] != timeMs_[b]) return timeMs_[a] < timeMs_[b];
        if (source_[a] != source_[b]) return source_[a] < source_[b];
        return recordId_[a] < recordId_[b];
    });
}

void EventStore::clearSeverity() { std::fill(severity_.begin(), severity_.end(), 0); }

size_t EventStore::memoryBytes() const {
    return pool_.bytes() + pool_.size() * (sizeof(std::string_view) + 48) + size() * (8 + 8 + 8 + 4 * 5 + 2 + 2 + 4) +
           keys_.size() * 8;
}

std::vector<uint32_t> EventStore::query(const QuerySpec& spec, const std::atomic<bool>* cancel) const {
    std::vector<uint32_t> out;
    const bool hasText = !spec.text.empty();

    std::regex re;
    std::string needle;
    int64_t numeric = -1;
    if (hasText) {
        if (spec.regex) {
            try {
                re = std::regex(spec.text, std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
            } catch (const std::regex_error& e) {
                throw std::runtime_error(std::string("invalid regular expression: ") + e.what());
            }
        } else {
            needle = foldCase(spec.text);
            if (needle.size() <= 6 && std::all_of(needle.begin(), needle.end(), [](char c) { return c >= '0' && c <= '9'; }))
                numeric = std::stoll(needle);
        }
    }

    // Per-distinct-string verdict cache: 0 = not evaluated, 1 = no match, 2 = match.
    std::vector<uint8_t> verdict(hasText ? pool_.size() : 0, 0);
    std::string folded;
    auto matches = [&](uint32_t id) {
        uint8_t& v = verdict[id];
        if (v == 0) {
            const std::string_view s = pool_.get(id);
            bool hit;
            if (spec.regex) {
                hit = std::regex_search(s.begin(), s.end(), re);
            } else {
                foldCaseInto(s, folded);
                hit = folded.find(needle) != std::string::npos;
            }
            v = hit ? 2 : 1;
        }
        return v == 2;
    };

    size_t n = 0;
    for (const uint32_t i : order_) {
        if (cancel && (++n & 0xFFFF) == 0 && cancel->load(std::memory_order_relaxed)) throw Cancelled();
        if (timeMs_[i] < spec.fromMs || timeMs_[i] > spec.toMs) continue;
        if (spec.eventId >= 0 && eventId_[i] != static_cast<uint32_t>(spec.eventId)) continue;
        if (severity_[i] < spec.minSeverity) continue;
        if (hasText) {
            bool hit = numeric >= 0 && eventId_[i] == static_cast<uint32_t>(numeric);
            if (!hit) hit = matches(provider_[i]) || matches(channel_[i]) || matches(computer_[i]);
            for (uint32_t k = fieldStart_[i], e = fieldStart_[i + 1]; !hit && k < e; ++k) hit = matches(vals_[k]);
            if (!hit) continue;
        }
        out.push_back(i);
    }
    return out;
}

// ---------------------------------------------------------------- persistence

namespace {

constexpr char kIndexMagic[8] = {'T', 'D', 'X', 'I', 'D', 'X', '0', '2'};

struct FileCloser {
    void operator()(std::FILE* f) const {
        if (f) std::fclose(f);
    }
};
using FilePtr = std::unique_ptr<std::FILE, FileCloser>;

void writeRaw(std::FILE* f, const void* p, size_t n) {
    if (n && std::fwrite(p, 1, n, f) != n) throw std::runtime_error("index write failed (storage full?)");
}
template <typename T>
void writeVec(std::FILE* f, const std::vector<T>& v) {
    const uint64_t n = v.size();
    writeRaw(f, &n, sizeof n);
    writeRaw(f, v.data(), v.size() * sizeof(T));
}
bool readRaw(std::FILE* f, void* p, size_t n) { return n == 0 || std::fread(p, 1, n, f) == n; }
template <typename T>
bool readVec(std::FILE* f, std::vector<T>& v, uint64_t maxCount) {
    uint64_t n = 0;
    if (!readRaw(f, &n, sizeof n) || n > maxCount) return false;
    v.resize(static_cast<size_t>(n));
    return readRaw(f, v.data(), v.size() * sizeof(T));
}

}  // namespace

void EventStore::save(const std::string& path) const {
    const std::string tmp = path + ".tmp";
    {
        FilePtr f(std::fopen(tmp.c_str(), "wb"));
        if (!f) throw std::runtime_error("cannot create index file " + tmp);
        writeRaw(f.get(), kIndexMagic, sizeof kIndexMagic);

        const uint64_t strings = pool_.size();
        writeRaw(f.get(), &strings, sizeof strings);
        for (uint32_t i = 0; i < strings; ++i) {
            const std::string_view s = pool_.get(i);
            const auto len = static_cast<uint32_t>(s.size());
            writeRaw(f.get(), &len, sizeof len);
            writeRaw(f.get(), s.data(), s.size());
        }
        const uint64_t srcs = sources_.size();
        writeRaw(f.get(), &srcs, sizeof srcs);
        for (const auto& s : sources_) {
            const auto len = static_cast<uint32_t>(s.size());
            writeRaw(f.get(), &len, sizeof len);
            writeRaw(f.get(), s.data(), s.size());
        }
        writeVec(f.get(), recordId_);
        writeVec(f.get(), timeMs_);
        writeVec(f.get(), fileOffset_);
        writeVec(f.get(), eventId_);
        writeVec(f.get(), provider_);
        writeVec(f.get(), channel_);
        writeVec(f.get(), computer_);
        writeVec(f.get(), fieldStart_);
        writeVec(f.get(), source_);
        writeVec(f.get(), level_);
        writeVec(f.get(), keys_);
        writeVec(f.get(), vals_);
        if (std::fflush(f.get()) != 0) throw std::runtime_error("index write failed (storage full?)");
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        throw std::runtime_error("cannot finalise index file " + path);
    }
}

bool EventStore::load(const std::string& path) {
    FilePtr f(std::fopen(path.c_str(), "rb"));
    if (!f) return false;
    char magic[sizeof kIndexMagic];
    if (!readRaw(f.get(), magic, sizeof magic) || std::memcmp(magic, kIndexMagic, sizeof magic) != 0) return false;

    clear();
    auto fail = [this] {
        clear();
        return false;
    };
    constexpr uint64_t kMax = 0xFFFFFFF0u;
    uint64_t strings = 0;
    if (!readRaw(f.get(), &strings, sizeof strings) || strings > kMax) return fail();
    std::string buf;
    for (uint64_t i = 0; i < strings; ++i) {
        uint32_t len = 0;
        if (!readRaw(f.get(), &len, sizeof len) || len > (1u << 30)) return fail();
        buf.resize(len);
        if (!readRaw(f.get(), buf.data(), len)) return fail();
        // Ids are positional; a snapshot always starts with "" followed by the well-known names,
        // so re-interning in order reproduces the saved ids exactly.
        if (pool_.intern(buf) != i) return fail();
    }
    uint64_t srcs = 0;
    if (!readRaw(f.get(), &srcs, sizeof srcs) || srcs > 0xFFFF) return fail();
    for (uint64_t i = 0; i < srcs; ++i) {
        uint32_t len = 0;
        if (!readRaw(f.get(), &len, sizeof len) || len > 65536) return fail();
        buf.resize(len);
        if (!readRaw(f.get(), buf.data(), len)) return fail();
        sources_.push_back(buf);
    }
    if (!readVec(f.get(), recordId_, kMax) || !readVec(f.get(), timeMs_, kMax) || !readVec(f.get(), fileOffset_, kMax) ||
        !readVec(f.get(), eventId_, kMax) || !readVec(f.get(), provider_, kMax) || !readVec(f.get(), channel_, kMax) ||
        !readVec(f.get(), computer_, kMax) || !readVec(f.get(), fieldStart_, kMax) || !readVec(f.get(), source_, kMax) ||
        !readVec(f.get(), level_, kMax) || !readVec(f.get(), keys_, kMax) || !readVec(f.get(), vals_, kMax))
        return fail();

    // Structural validation so a damaged snapshot can never cause out-of-bounds access later.
    const size_t n = recordId_.size();
    const auto poolSize = static_cast<uint32_t>(pool_.size());
    auto idsOk = [poolSize](const std::vector<uint32_t>& v) {
        return std::all_of(v.begin(), v.end(), [poolSize](uint32_t id) { return id < poolSize; });
    };
    if (timeMs_.size() != n || fileOffset_.size() != n || eventId_.size() != n || provider_.size() != n ||
        channel_.size() != n || computer_.size() != n || source_.size() != n || level_.size() != n ||
        fieldStart_.size() != n + 1 || keys_.size() != vals_.size() || fieldStart_.front() != 0 ||
        fieldStart_.back() != keys_.size() || !std::is_sorted(fieldStart_.begin(), fieldStart_.end()) ||
        !idsOk(provider_) || !idsOk(channel_) || !idsOk(computer_) || !idsOk(keys_) || !idsOk(vals_) ||
        !std::all_of(source_.begin(), source_.end(), [this](uint16_t s) { return s < sources_.size(); }))
        return fail();

    severity_.assign(n, 0);
    resolveWellKnown();
    finalize();
    return true;
}

}  // namespace td
