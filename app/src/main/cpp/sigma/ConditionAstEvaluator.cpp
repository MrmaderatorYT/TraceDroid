// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "sigma/ConditionAstEvaluator.hpp"

#include <algorithm>

namespace td::sigma {

EventContext::EventContext(const EventStore& store) : store_(store) {}

void EventContext::bind(uint32_t i) {
    keys_.clear();
    raw_.clear();
    const auto& wk = store_.wk();
    // System-level attributes come first so that `EventID`, `Channel`, ... always resolve to the
    // record's own metadata even if an EventData field happens to share the name.
    eventIdText_ = std::to_string(store_.eventId(i));
    keys_.push_back(wk.EventID);
    raw_.push_back(eventIdText_);
    keys_.push_back(wk.Channel);
    raw_.push_back(store_.str(store_.channelId(i)));
    keys_.push_back(wk.Provider_Name);
    raw_.push_back(store_.str(store_.providerId(i)));
    keys_.push_back(wk.Computer);
    raw_.push_back(store_.str(store_.computerId(i)));

    const auto fk = store_.fieldKeys(i);
    const auto fv = store_.fieldVals(i);
    for (size_t k = 0; k < fk.size(); ++k) {
        keys_.push_back(fk[k]);
        raw_.push_back(store_.str(fv[k]));
    }
    if (folded_.size() < keys_.size()) folded_.resize(keys_.size());
    foldedReady_.assign(keys_.size(), 0);
}

std::string_view EventContext::foldedAt(size_t slot) {
    if (!foldedReady_[slot]) {
        foldCaseInto(raw_[slot], folded_[slot]);
        foldedReady_[slot] = 1;
    }
    return folded_[slot];
}

int EventContext::find(uint32_t keyId) const {
    for (size_t i = 0; i < keys_.size(); ++i)
        if (keys_[i] == keyId) return static_cast<int>(i);
    return -1;
}

bool ConditionAstEvaluator::evaluate(const CompiledRule& rule, EventContext& ctx, std::vector<uint32_t>& matchedKeys) const {
    matchedKeys.clear();
    if (!rule.condition || !evalNode(rule, *rule.condition, ctx, matchedKeys)) {
        matchedKeys.clear();
        return false;
    }
    std::sort(matchedKeys.begin(), matchedKeys.end());
    matchedKeys.erase(std::unique(matchedKeys.begin(), matchedKeys.end()), matchedKeys.end());
    return true;
}

bool ConditionAstEvaluator::evalNode(const CompiledRule& rule, const ConditionNode& node, EventContext& ctx,
                                     std::vector<uint32_t>& hits) const {
    const size_t mark = hits.size();
    switch (node.kind) {
        case ConditionNode::Kind::And:
            if (evalNode(rule, *node.left, ctx, hits) && evalNode(rule, *node.right, ctx, hits)) return true;
            hits.resize(mark);
            return false;
        case ConditionNode::Kind::Or:
            if (evalNode(rule, *node.left, ctx, hits)) return true;
            hits.resize(mark);
            if (evalNode(rule, *node.right, ctx, hits)) return true;
            hits.resize(mark);
            return false;
        case ConditionNode::Kind::Not: {
            // Fields that satisfied a negated branch are not evidence for the alert.
            const bool inner = evalNode(rule, *node.left, ctx, hits);
            hits.resize(mark);
            return !inner;
        }
        case ConditionNode::Kind::Selection:
            return evalSelection(rule.selections[static_cast<size_t>(node.selection)], ctx, hits);
        case ConditionNode::Kind::Quantified: {
            int matched = 0;
            for (const int idx : node.group) {
                const bool ok = evalSelection(rule.selections[static_cast<size_t>(idx)], ctx, hits);
                if (ok) {
                    ++matched;
                    if (node.required > 0 && matched >= node.required) return true;
                } else if (node.required == 0) {  // "all of": one miss decides
                    hits.resize(mark);
                    return false;
                }
            }
            if (node.required == 0) return true;
            hits.resize(mark);
            return false;
        }
    }
    return false;
}

bool ConditionAstEvaluator::evalSelection(const Selection& sel, EventContext& ctx, std::vector<uint32_t>& hits) const {
    const size_t mark = hits.size();
    for (const SelectionItem& item : sel.alternatives) {
        bool all = true;
        for (const FieldMatcher& fm : item.fields) {
            if (!evalField(fm, ctx, hits)) {
                all = false;
                break;
            }
        }
        if (all) return true;
        hits.resize(mark);
    }
    return false;
}

bool ConditionAstEvaluator::evalField(const FieldMatcher& fm, EventContext& ctx, std::vector<uint32_t>& hits) const {
    using Kind = ValueMatcher::Kind;

    if (fm.field.empty()) {
        // Keyword search: the value may appear in any field of the event.
        const size_t mark = hits.size();
        auto anySlot = [&](const ValueMatcher& vm) {
            for (size_t s = 0; s < ctx.slotCount(); ++s) {
                if (ctx.rawAt(s).empty()) continue;
                if (vm.matches(ctx.rawAt(s), vm.cased || vm.kind == Kind::Regex ? ctx.rawAt(s) : ctx.foldedAt(s))) {
                    hits.push_back(ctx.keyAt(s));
                    return true;
                }
            }
            return false;
        };
        if (fm.matchAll) {
            for (const auto& vm : fm.values) {
                if (!anySlot(vm)) {
                    hits.resize(mark);
                    return false;
                }
            }
            return true;
        }
        for (const auto& vm : fm.values)
            if (anySlot(vm)) return true;
        return false;
    }

    const int slot = fm.keyId == UINT32_MAX ? -1 : ctx.find(fm.keyId);
    auto one = [&](const ValueMatcher& vm) {
        if (slot < 0) {
            // Absent field: only "is null" and "exists: false" can be satisfied.
            return vm.kind == Kind::IsNull || (vm.kind == Kind::Exists && !vm.expectExists);
        }
        const auto s = static_cast<size_t>(slot);
        const bool needFolded = !vm.cased && vm.kind != Kind::Regex && vm.kind != Kind::IsNull && vm.kind != Kind::Exists &&
                                vm.kind != Kind::NumCompare && vm.kind != Kind::Cidr;
        return vm.matches(ctx.rawAt(s), needFolded ? ctx.foldedAt(s) : ctx.rawAt(s));
    };
    bool ok;
    if (fm.matchAll) ok = std::all_of(fm.values.begin(), fm.values.end(), one);
    else ok = std::any_of(fm.values.begin(), fm.values.end(), one);
    if (ok && slot >= 0) hits.push_back(fm.keyId);
    return ok;
}

}  // namespace td::sigma
