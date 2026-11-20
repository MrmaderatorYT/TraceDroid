// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#pragma once

#include <atomic>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

#include "sigma/ConditionAstEvaluator.hpp"
#include "sigma/SigmaRuleCompiler.hpp"
#include "store/EventStore.hpp"

namespace td::sigma {

/// One (event, rule) match. `keyStart/keyCount` slice SigmaEngine::hitKeys().
struct SigmaHit {
    uint32_t eventIndex;
    uint32_t ruleIndex;
    uint32_t keyStart;
    uint32_t keyCount;
};

/// Owns the loaded rule pack and the results of the last batch scan.
class SigmaEngine {
public:
    /// Compiles rules from YAML text. Returns the number of rules added (duplicates by id are ignored).
    size_t loadRules(std::string_view yaml, const std::string& sourceFile);
    /// Loads a .yml/.yaml file, or every such file below a directory. Returns the number of rules added.
    size_t loadPath(const std::string& path);
    void clearRules();

    const std::vector<CompiledRule>& rules() const { return rules_; }
    const std::vector<RuleDiagnostic>& diagnostics() const { return diagnostics_; }

    /// Evaluates every applicable rule against every event (multi-threaded), records the hits and
    /// raises each matching event's severity in the store. Throws Cancelled if `cancel` is raised.
    void scan(EventStore& store, const ProgressFn& progress, const std::atomic<bool>& cancel);
    void clearResults();

    const std::vector<SigmaHit>& hits() const { return hits_; }
    std::span<const uint32_t> hitKeys(const SigmaHit& h) const { return {keys_.data() + h.keyStart, h.keyCount}; }
    /// Hits for one event (hits are ordered by event index).
    std::span<const SigmaHit> hitsForEvent(uint32_t eventIndex) const;
    const std::vector<uint32_t>& ruleHitCounts() const { return ruleHitCounts_; }

private:
    void resolveAgainst(const EventStore& store);

    std::vector<CompiledRule> rules_;
    std::vector<RuleDiagnostic> diagnostics_;
    std::unordered_set<std::string> ruleIds_;
    std::vector<SigmaHit> hits_;
    std::vector<uint32_t> keys_;
    std::vector<uint32_t> ruleHitCounts_;
};

}  // namespace td::sigma
