// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "yara/YaraEngineWrapper.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

#include "common/Util.hpp"

#if TD_HAVE_YARA
#include <yara.h>
#endif

namespace td::yara {

#if TD_HAVE_YARA

namespace {

constexpr size_t kMaxRuleMatches = 2000;
constexpr size_t kMaxStringsPerRule = 64;
constexpr size_t kContextBefore = 16;
constexpr size_t kContextSize = 64;
constexpr uint64_t kMaxInMemoryScan = 512ULL << 20;

struct CompilerDeleter {
    void operator()(YR_COMPILER* c) const {
        if (c) yr_compiler_destroy(c);
    }
};
using CompilerPtr = std::unique_ptr<YR_COMPILER, CompilerDeleter>;

struct CompileErrors {
    std::string file;
    std::vector<std::string>* sink;
    int errors = 0;
};

void compilerCallback(int level, const char* /*fileName*/, int line, const YR_RULE* /*rule*/, const char* message,
                      void* userData) {
    auto* ctx = static_cast<CompileErrors*>(userData);
    if (level != YARA_ERROR_LEVEL_ERROR) return;  // warnings (slow rules etc.) do not block loading
    ++ctx->errors;
    if (ctx->sink && ctx->sink->size() < 500)
        ctx->sink->push_back(ctx->file + ":" + std::to_string(line) + ": " + (message ? message : "error"));
}

// Rules are sandboxed to the pack itself: `include` must not read arbitrary files from the device.
const char* denyInclude(const char*, const char*, const char*, void*) { return nullptr; }

CompilerPtr newCompiler(CompileErrors* errors) {
    YR_COMPILER* raw = nullptr;
    if (yr_compiler_create(&raw) != ERROR_SUCCESS) throw std::runtime_error("libyara: cannot create compiler");
    CompilerPtr compiler(raw);
    yr_compiler_set_callback(raw, compilerCallback, errors);
    yr_compiler_set_include_callback(raw, denyInclude, nullptr, nullptr);
    return compiler;
}

std::string describeError(int code) {
    switch (code) {
        case ERROR_INSUFFICIENT_MEMORY: return "insufficient memory";
        case ERROR_COULD_NOT_OPEN_FILE: return "could not open file";
        case ERROR_COULD_NOT_MAP_FILE: return "could not map file";
        case ERROR_TOO_MANY_SCAN_THREADS: return "too many scan threads";
        case ERROR_SCAN_TIMEOUT: return "scan timed out";
        case ERROR_CALLBACK_ERROR: return "callback error";
        case ERROR_TOO_MANY_MATCHES: return "too many matches";
        default: return "libyara error " + std::to_string(code);
    }
}

struct ScanState {
    ScanResult* result;
    int fd;                      // >= 0: context bytes are read with pread
    const uint8_t* memory;       // otherwise from the in-memory copy
    size_t memorySize;
};

void readContext(const ScanState& st, uint64_t offset, StringMatch& out) {
    const uint64_t start = offset > kContextBefore ? offset - kContextBefore : 0;
    out.contextOffset = start;
    out.context.resize(kContextSize);
    size_t got = 0;
    if (st.memory) {
        if (start < st.memorySize) {
            got = std::min<size_t>(kContextSize, st.memorySize - static_cast<size_t>(start));
            std::memcpy(out.context.data(), st.memory + start, got);
        }
    } else if (st.fd >= 0) {
        const ssize_t n = ::pread(st.fd, out.context.data(), kContextSize, static_cast<off_t>(start));
        if (n > 0) got = static_cast<size_t>(n);
    }
    out.context.resize(got);
}

int scanCallback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    auto* st = static_cast<ScanState*>(userData);
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    if (st->result->matches.size() >= kMaxRuleMatches) return CALLBACK_ABORT;

    auto* rule = static_cast<YR_RULE*>(messageData);
    RuleMatch m;
    m.rule = rule->identifier ? rule->identifier : "";
    m.ns = rule->ns && rule->ns->name ? rule->ns->name : "";

    const char* tag = nullptr;
    yr_rule_tags_foreach(rule, tag) { m.tags.emplace_back(tag); }

    YR_META* meta = nullptr;
    yr_rule_metas_foreach(rule, meta) {
        MetaValue mv;
        mv.name = meta->identifier ? meta->identifier : "";
        if (meta->type == META_TYPE_INTEGER) {
            mv.type = 'i';
            mv.value = std::to_string(meta->integer);
        } else if (meta->type == META_TYPE_BOOLEAN) {
            mv.type = 'b';
            mv.value = meta->integer ? "true" : "false";
        } else {
            mv.type = 's';
            mv.value = meta->string ? meta->string : "";
        }
        m.metas.push_back(std::move(mv));
    }

    YR_STRING* string = nullptr;
    yr_rule_strings_foreach(rule, string) {
        YR_MATCH* match = nullptr;
        yr_string_matches_foreach(context, string, match) {
            ++m.totalStringMatches;
            if (m.strings.size() >= kMaxStringsPerRule) continue;
            StringMatch sm;
            sm.identifier = string->identifier ? string->identifier : "";
            sm.offset = static_cast<uint64_t>(match->base + match->offset);
            sm.length = static_cast<uint32_t>(match->match_length);
            readContext(*st, sm.offset, sm);
            m.strings.push_back(std::move(sm));
        }
    }
    std::sort(m.strings.begin(), m.strings.end(),
              [](const StringMatch& a, const StringMatch& b) { return a.offset < b.offset; });
    st->result->matches.push_back(std::move(m));
    return CALLBACK_CONTINUE;
}

}  // namespace

bool YaraEngineWrapper::available() { return true; }

YaraEngineWrapper::YaraEngineWrapper() {
    if (yr_initialize() != ERROR_SUCCESS) throw std::runtime_error("libyara: initialisation failed");
    initialized_ = true;
}

YaraEngineWrapper::~YaraEngineWrapper() {
    clear();
    if (initialized_) yr_finalize();
}

void YaraEngineWrapper::clear() {
    if (rules_) yr_rules_destroy(rules_);
    rules_ = nullptr;
    ruleCount_ = 0;
    errors_.clear();
}

size_t YaraEngineWrapper::compilePath(const std::string& path) {
    namespace fs = std::filesystem;
    clear();

    std::vector<fs::path> files;
    std::error_code ec;
    const fs::path root(path);
    auto isRuleFile = [](const fs::path& p) {
        const std::string ext = foldCase(p.extension().string());
        return ext == ".yar" || ext == ".yara";
    };
    if (fs::is_regular_file(root, ec)) {
        files.push_back(root);
    } else if (fs::is_directory(root, ec)) {
        for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end;
             it.increment(ec)) {
            if (ec) break;
            if (it->is_regular_file(ec) && isRuleFile(it->path())) files.push_back(it->path());
        }
        std::sort(files.begin(), files.end());
    } else {
        throw std::runtime_error("YARA rule path does not exist: " + path);
    }

    CompileErrors mainErrors{"", &errors_, 0};
    CompilerPtr compiler = newCompiler(&mainErrors);
    std::vector<std::pair<std::string, std::string>> accepted;  // (namespace, source)
    for (const auto& file : files) {
        std::ifstream in(file, std::ios::binary);
        if (!in) {
            errors_.push_back(file.filename().string() + ": cannot read file");
            continue;
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        const std::string source = ss.str();
        // The namespace is the path inside the pack, so equal rule names in different files coexist.
        std::string name = fs::is_directory(root, ec) ? fs::relative(file, root, ec).generic_string() : std::string();
        if (name.empty()) name = file.filename().string();

        // A libyara compiler is unusable after its first error, so every file is test-compiled in
        // a throw-away compiler first; only clean files reach the real one.
        CompileErrors probeErrors{name, &errors_, 0};
        {
            CompilerPtr probe = newCompiler(&probeErrors);
            yr_compiler_add_string(probe.get(), source.c_str(), name.c_str());
        }
        if (probeErrors.errors > 0) continue;

        mainErrors.file = name;
        mainErrors.errors = 0;
        if (yr_compiler_add_string(compiler.get(), source.c_str(), name.c_str()) > 0 || mainErrors.errors > 0) {
            // Clean in isolation but conflicting with an earlier file. The compiler is now poisoned:
            // rebuild it from the files accepted so far and leave this one out.
            errors_.push_back(name + ": skipped (conflicts with a previously loaded rule file)");
            mainErrors.file.clear();
            compiler = newCompiler(&mainErrors);
            for (const auto& [ns, src] : accepted) yr_compiler_add_string(compiler.get(), src.c_str(), ns.c_str());
            continue;
        }
        accepted.emplace_back(name, source);
    }
    if (accepted.empty()) return 0;

    YR_RULES* rules = nullptr;
    const int rc = yr_compiler_get_rules(compiler.get(), &rules);
    if (rc != ERROR_SUCCESS) throw std::runtime_error("libyara: " + describeError(rc));
    rules_ = rules;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(rules_, rule) { ++ruleCount_; }
    return ruleCount_;
}

ScanResult YaraEngineWrapper::scanFd(int fd, int timeoutSeconds) const {
    ScanResult result;
    if (!rules_) {
        result.error = "no YARA rules are loaded";
        return result;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        result.error = std::string("cannot stat artifact: ") + std::strerror(errno);
        return result;
    }
    const int timeout = timeoutSeconds > 0 ? timeoutSeconds : 0;
    ScanState state{&result, -1, nullptr, 0};
    int rc;

    if (S_ISREG(st.st_mode) && st.st_size > 0) {
        // Regular file: libyara maps it, so even multi-gigabyte memory dumps are not copied.
        result.bytesScanned = static_cast<uint64_t>(st.st_size);
        state.fd = fd;
        rc = yr_rules_scan_fd(rules_, fd, 0, scanCallback, &state, timeout);
    } else if (S_ISREG(st.st_mode)) {
        return result;  // empty file: nothing to match
    } else {
        // Pipe/socket-backed document providers cannot be mapped; read the stream into memory.
        std::vector<uint8_t> buffer;
        uint8_t chunk[1 << 16];
        for (;;) {
            const ssize_t n = ::read(fd, chunk, sizeof chunk);
            if (n < 0) {
                if (errno == EINTR) continue;
                result.error = std::string("cannot read artifact: ") + std::strerror(errno);
                return result;
            }
            if (n == 0) break;
            if (buffer.size() + static_cast<size_t>(n) > kMaxInMemoryScan) {
                result.error = "streamed artifact exceeds the 512 MiB in-memory limit; import it into the case first";
                return result;
            }
            buffer.insert(buffer.end(), chunk, chunk + n);
        }
        result.bytesScanned = buffer.size();
        if (buffer.empty()) return result;
        state.memory = buffer.data();
        state.memorySize = buffer.size();
        rc = yr_rules_scan_mem(rules_, buffer.data(), buffer.size(), 0, scanCallback, &state, timeout);
    }

    if (rc == ERROR_SCAN_TIMEOUT) result.timedOut = true;
    else if (rc != ERROR_SUCCESS && rc != ERROR_CALLBACK_ERROR) result.error = describeError(rc);
    return result;
}

#else  // !TD_HAVE_YARA

bool YaraEngineWrapper::available() { return false; }
YaraEngineWrapper::YaraEngineWrapper() = default;
YaraEngineWrapper::~YaraEngineWrapper() = default;
void YaraEngineWrapper::clear() {
    ruleCount_ = 0;
    errors_.clear();
}
size_t YaraEngineWrapper::compilePath(const std::string&) {
    throw std::runtime_error("this build does not include libyara (configure with -DTD_WITH_YARA=ON)");
}
ScanResult YaraEngineWrapper::scanFd(int, int) const {
    ScanResult r;
    r.error = "this build does not include libyara";
    return r;
}

#endif

}  // namespace td::yara
