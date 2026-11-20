// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace td {

/// Thrown for malformed input (corrupt EVTX structures, bad YAML, ...).
class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Thrown when a long-running operation observes the session's cancel flag.
class Cancelled : public std::runtime_error {
public:
    Cancelled() : std::runtime_error("operation cancelled") {}
};

/// Progress sink: (stage, current, total). Called on the thread that started the operation.
using ProgressFn = std::function<void(int stage, uint64_t current, uint64_t total)>;

enum ProgressStage : int {
    kStageParse = 1,
    kStageIndex = 2,
    kStageSigma = 3,
    kStageGraph = 4,
    kStageYara = 5,
};

// ---- unaligned little-endian loads (all supported ABIs are little-endian) ----
template <typename T>
inline T loadLe(const uint8_t* p) noexcept {
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

// ---- text helpers ----
void appendUtf8(std::string& out, uint32_t codepoint);
/// Decodes `units` UTF-16LE code units; stops at an embedded NUL when stopAtNul is set.
void utf16leToUtf8(const uint8_t* p, size_t units, std::string& out, bool stopAtNul = true);
std::u16string utf8ToUtf16(std::string_view in);
/// Unicode-aware simple case folding for ASCII, Latin-1, Greek and Cyrillic; other code points pass through.
std::string foldCase(std::string_view in);
void foldCaseInto(std::string_view in, std::string& out);
std::string_view trim(std::string_view s);
bool iequalsAscii(std::string_view a, std::string_view b);

std::string base64Encode(std::string_view bytes);
std::string hexEncode(const uint8_t* p, size_t n, bool upper = true);

// ---- time helpers ----
/// Windows FILETIME (100 ns ticks since 1601) to Unix epoch milliseconds.
int64_t filetimeToUnixMs(uint64_t filetime);
/// "2024-01-31T12:34:56.1234567Z"
std::string formatFiletimeIso(uint64_t filetime);
/// "2024-01-31 12:34:56.123"
std::string formatUnixMs(int64_t ms);
/// Parses "YYYY-MM-DD[T ]HH:MM:SS[.fraction][Z]" to Unix ms; returns false when not parseable.
bool parseTimestampMs(std::string_view s, int64_t& outMs);

// ---- minimal JSON writer (output only; Java parses with org.json) ----
class JsonWriter {
public:
    JsonWriter& beginObject();
    JsonWriter& endObject();
    JsonWriter& beginArray();
    JsonWriter& endArray();
    JsonWriter& key(std::string_view k);
    JsonWriter& value(std::string_view v);
    JsonWriter& value(const char* v) { return value(std::string_view(v)); }
    JsonWriter& value(int64_t v);
    JsonWriter& value(uint64_t v);
    JsonWriter& value(int v) { return value(static_cast<int64_t>(v)); }
    JsonWriter& value(uint32_t v) { return value(static_cast<uint64_t>(v)); }
    JsonWriter& value(double v);
    JsonWriter& value(bool v);
    template <typename T>
    JsonWriter& kv(std::string_view k, T&& v) {
        key(k);
        return value(std::forward<T>(v));
    }
    std::string take() { return std::move(out_); }
    const std::string& str() const { return out_; }

private:
    void comma();
    std::string out_;
    std::vector<bool> first_;
    bool afterKey_ = false;
};

/// Little-endian binary appender used for the Java-facing direct buffers.
class ByteWriter {
public:
    template <typename T>
    void put(T v) {
        const auto* p = reinterpret_cast<const uint8_t*>(&v);
        buf_.insert(buf_.end(), p, p + sizeof(T));
    }
    /// u16 length prefix + UTF-8 bytes (truncated on a code point boundary to maxBytes).
    void putString(std::string_view s, size_t maxBytes = 0xFFFF);
    std::vector<uint8_t>& buffer() { return buf_; }
    size_t size() const { return buf_.size(); }

private:
    std::vector<uint8_t> buf_;
};

}  // namespace td
