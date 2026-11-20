// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "sigma/SigmaEngine.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

namespace td::sigma {

size_t SigmaEngine::loadRules(std::string_view yaml, const std::string& sourceFile) {
    SigmaRuleCompiler compiler;
    auto compiled = compiler.compile(yaml, sourceFile, diagnostics_);
    size_t added = 0;
    for (auto& rule : compiled) {
        const std::string key = rule.id.empty() ? rule.sourceFile + "#" + rule.title : rule.id;
        if (!ruleIds_.insert(key).second) continue;  // same rule imported twice
        rules_.push_back(std::move(rule));
        ++added;
    }
    return added;
}

size_t SigmaEngine::loadPath(const std::string& path) {
    namespace fs = std::filesystem;
    auto isRuleFile = [](const fs::path& p) {
        const std::string ext = foldCase(p.extension().string());
        return ext == ".yml" || ext == ".yaml";
    };
    auto loadFile = [this](const fs::path& p) -> size_t {
        std::ifstream in(p, std::ios::binary);
        if (!in) {
            diagnostics_.push_back({p.string(), {}, "cannot read file"});
            return 0;
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        return loadRules(ss.str(), p.filename().string());
    };

    std::error_code ec;
    const fs::path root(path);
    if (fs::is_regular_file(root, ec)) return loadFile(root);
    if (!fs::is_directory(root, ec)) throw std::runtime_error("rule path does not exist: " + path);

    std::vector<fs::path> files;
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end;
         it.increment(ec)) {
        if (ec) break;
        if (it->is_regular_file(ec) && isRuleFile(it->path())) files.push_back(it->path());
    }
    std::sort(files.begin(), files.end());
    size_t added = 0;
    for (const auto& f : files) added += loadFile(f);
    return added;
}

void SigmaEngine::clearRules() {
    rules_.clear();
    diagnostics_.clear();
    ruleIds_.clear();
    clearResults();
}

void SigmaEngine::clearResults() {
    hits_.clear();
    keys_.clear();
    ruleHitCounts_.clear();
}

std::span<const SigmaHit> SigmaEngine::hitsForEvent(uint32_t eventIndex) const {
    const auto range = std::equal_range(hits_.begin(), hits_.end(), eventIndex, [](const auto& a, const auto& b) {
        struct Key {
            static uint32_t of(const SigmaHit& h) { return h.eventIndex; }
            static uint32_t of(uint32_t v) { return v; }
        };
        return Key::of(a) < Key::of(b);
    });
    return {hits_.data() + (range.first - hits_.begin()), static_cast<size_t>(range.second - range.first)};
}

void SigmaEngine::resolveAgainst(const EventStore& store) {
    const StringPool& pool = store.pool();
    for (CompiledRule& rule : rules_) {
        for (Selection& sel : rule.selections)
            for (SelectionItem& item : sel.alternatives)
                for (FieldMatcher& fm : item.fields)
                    fm.keyId = fm.field.empty() ? UINT32_MAX : pool.find(fm.field).value_or(UINT32_MAX);

        LogSourceFilter& src = rule.source;
        src.channelIds.clear();
        src.resolvable = true;
        for (const std::string& channel : src.channels)
            if (const auto id = pool.find(channel)) src.channelIds.push_back(*id);
        // A rule bound to channels that do not occur in this dataset can never match.
        if (!src.channels.empty() && src.channelIds.empty()) src.resolvable = false;
    }
}

void SigmaEngine::scan(EventStore& store, const ProgressFn& progress, const std::atomic<bool>& cancel) {
    clearResults();
    store.clearSeverity();
    ruleHitCounts_.assign(rules_.size(), 0);
    const auto total = static_cast<uint32_t>(store.size());
    if (rules_.empty() || total == 0) {
        if (progress) progress(kStageSigma, total, total);
        return;
    }
    resolveAgainst(store);

    struct Partial {
        std::vector<SigmaHit> hits;
        std::vector<uint32_t> keys;
    };
    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    const unsigned workers = std::min<unsigned>({hw, 8u, total / 2048 + 1});
    std::vector<Partial> partials(workers);
    std::atomic<uint64_t> done{0};
    std::atomic<bool> failed{false};
    std::exception_ptr error;
    std::mutex errorMutex;

    auto work = [&](unsigned w, uint32_t begin, uint32_t end) {
        try {
            Partial& out = partials[w];
            EventContext ctx(store);
            ConditionAstEvaluator evaluator;
            std::vector<uint32_t> matched;
            // (channel id, event id) -> rules whose logsource admits such events.
            std::unordered_map<uint64_t, std::vector<uint32_t>> applicable;
            uint32_t sinceReport = 0;

            for (uint32_t i = begin; i < end; ++i) {
                if (++sinceReport == 2048) {
                    done.fetch_add(sinceReport, std::memory_order_relaxed);
                    sinceReport = 0;
                    if (cancel.load(std::memory_order_relaxed) || failed.load(std::memory_order_relaxed)) return;
                }
                const uint32_t channel = store.channelId(i), eventId = store.eventId(i);
                const uint64_t key = (static_cast<uint64_t>(channel) << 32) | eventId;
                auto it = applicable.find(key);
                if (it == applicable.end()) {
                    std::vector<uint32_t> list;
                    for (uint32_t r = 0; r < rules_.size(); ++r) {
                        const LogSourceFilter& src = rules_[r].source;
                        if (!src.resolvable) continue;
                        if (!src.channelIds.empty() &&
                            std::find(src.channelIds.begin(), src.channelIds.end(), channel) == src.channelIds.end())
                            continue;
                        if (!src.eventIds.empty() &&
                            std::find(src.eventIds.begin(), src.eventIds.end(), eventId) == src.eventIds.end())
                            continue;
                        list.push_back(r);
                    }
                    it = applicable.emplace(key, std::move(list)).first;
                }
                if (it->second.empty()) continue;

                ctx.bind(i);
                for (const uint32_t r : it->second) {
                    if (!evaluator.evaluate(rules_[r], ctx, matched)) continue;
                    out.hits.push_back({i, r, static_cast<uint32_t>(out.keys.size()), static_cast<uint32_t>(matched.size())});
                    out.keys.insert(out.keys.end(), matched.begin(), matched.end());
                }
            }
            done.fetch_add(sinceReport, std::memory_order_relaxed);
        } catch (...) {
            const std::lock_guard lock(errorMutex);
            if (!error) error = std::current_exception();
            failed.store(true);
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(workers);
    std::atomic<unsigned> finished{0};
    const uint32_t slice = total / workers + 1;
    for (unsigned w = 0; w < workers; ++w) {
        const uint32_t begin = std::min<uint64_t>(static_cast<uint64_t>(w) * slice, total);
        const uint32_t end = std::min<uint64_t>(static_cast<uint64_t>(begin) + slice, total);
        threads.emplace_back([&, w, begin, end] {
            work(w, begin, end);
            finished.fetch_add(1);
        });
    }
    // The calling thread owns the JNI environment, so it is the one that reports progress.
    while (finished.load() < workers) {
        if (progress) progress(kStageSigma, done.load(std::memory_order_relaxed), total);
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }
    for (auto& t : threads) t.join();
    if (error) std::rethrow_exception(error);
    if (cancel.load()) throw Cancelled();

    // Partials cover ascending, disjoint event ranges, so concatenation keeps hits ordered by event.
    for (Partial& p : partials) {
        const auto keyBase = static_cast<uint32_t>(keys_.size());
        for (SigmaHit h : p.hits) {
            h.keyStart += keyBase;
            hits_.push_back(h);
            ++ruleHitCounts_[h.ruleIndex];
            store.raiseSeverity(h.eventIndex, static_cast<uint8_t>(rules_[h.ruleIndex].level));
        }
        keys_.insert(keys_.end(), p.keys.begin(), p.keys.end());
        p = Partial{};
    }
    if (progress) progress(kStageSigma, total, total);
}

}  // namespace td::sigma
