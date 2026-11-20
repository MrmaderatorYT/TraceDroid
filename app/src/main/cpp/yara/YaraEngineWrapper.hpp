// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// RAII wrapper around libyara: compiles .yar/.yara rule files and scans artifacts by file descriptor.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

struct YR_RULES;

namespace td::yara {

struct StringMatch {
    std::string identifier;        // "$a", "$mz", ...
    uint64_t offset = 0;           // absolute offset in the scanned artifact
    uint32_t length = 0;           // full match length
    uint64_t contextOffset = 0;    // offset of the first byte in `context`
    std::vector<uint8_t> context;  // bytes surrounding the match, for the hex preview
};

struct MetaValue {
    std::string name;
    std::string value;
    char type = 's';  // 's' string, 'i' integer, 'b' boolean
};

struct RuleMatch {
    std::string rule;
    std::string ns;
    std::vector<std::string> tags;
    std::vector<MetaValue> metas;
    std::vector<StringMatch> strings;
    uint32_t totalStringMatches = 0;  // may exceed strings.size() when the per-rule cap is hit
};

struct ScanResult {
    std::vector<RuleMatch> matches;
    uint64_t bytesScanned = 0;
    bool timedOut = false;
    std::string error;  // empty on success
};

class YaraEngineWrapper {
public:
    YaraEngineWrapper();
    ~YaraEngineWrapper();
    YaraEngineWrapper(const YaraEngineWrapper&) = delete;
    YaraEngineWrapper& operator=(const YaraEngineWrapper&) = delete;

    /// False when the binary was built without libyara.
    static bool available();

    /// Compiles a rule file, or every .yar/.yara file below a directory, replacing the current rule set.
    /// Files that fail to compile are skipped and reported via errors(). Returns the number of rules loaded.
    size_t compilePath(const std::string& path);
    void clear();
    size_t ruleCount() const { return ruleCount_; }
    const std::vector<std::string>& errors() const { return errors_; }

    /// Scans the artifact behind `fd` (not closed by this call). `timeoutSeconds` <= 0 means no limit.
    ScanResult scanFd(int fd, int timeoutSeconds) const;

private:
    YR_RULES* rules_ = nullptr;
    size_t ruleCount_ = 0;
    std::vector<std::string> errors_;
    bool initialized_ = false;
};

}  // namespace td::yara
