// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sigma/SigmaRuleCompiler.hpp"
#include "store/EventStore.hpp"

namespace td::sigma {

/// Per-thread view of one event for rule evaluation. Field values are case-folded lazily and
/// at most once per event, no matter how many rules inspect them.
class EventContext {
public:
    explicit EventContext(const EventStore& store);
    void bind(uint32_t eventIndex);

    size_t slotCount() const { return keys_.size(); }
    uint32_t keyAt(size_t slot) const { return keys_[slot]; }
    std::string_view rawAt(size_t slot) const { return raw_[slot]; }
    std::string_view foldedAt(size_t slot);
    /// Slot holding field `keyId`, or -1 when the event has no such field.
    int find(uint32_t keyId) const;

private:
    const EventStore& store_;
    std::vector<uint32_t> keys_;
    std::vector<std::string_view> raw_;
    std::vector<std::string> folded_;
    std::vector<uint8_t> foldedReady_;
    std::string eventIdText_;
};

/// Evaluates a compiled rule's condition AST against an event.
class ConditionAstEvaluator {
public:
    /// Returns true when the rule matches. `matchedKeys` receives the pool ids of the fields whose
    /// values satisfied positive (non-negated) parts of the condition, for highlighting.
    bool evaluate(const CompiledRule& rule, EventContext& ctx, std::vector<uint32_t>& matchedKeys) const;

private:
    bool evalNode(const CompiledRule& rule, const ConditionNode& node, EventContext& ctx, std::vector<uint32_t>& hits) const;
    bool evalSelection(const Selection& sel, EventContext& ctx, std::vector<uint32_t>& hits) const;
    bool evalField(const FieldMatcher& fm, EventContext& ctx, std::vector<uint32_t>& hits) const;
};

}  // namespace td::sigma
