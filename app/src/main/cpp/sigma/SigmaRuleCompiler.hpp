// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Compiles Sigma rules (https://sigmahq.io specification) from YAML into an executable form:
// a logsource filter, a set of named selections made of field matchers, and a condition AST.
#pragma once

#include <cstdint>
#include <memory>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "sigma/YamlParser.hpp"

namespace td::sigma {

enum class Level : uint8_t { None = 0, Informational = 1, Low = 2, Medium = 3, High = 4, Critical = 5 };
std::string_view levelName(Level l);

/// A single compiled value pattern. Plain Sigma values become case-insensitive globs
/// (`*` / `?` wildcards); the common shapes are recognised so matching is a memcmp or a find.
struct ValueMatcher {
    enum class Kind : uint8_t { Equals, Contains, StartsWith, EndsWith, Glob, Regex, IsNull, Exists, NumCompare, Cidr };
    enum class Cmp : uint8_t { Lt, Lte, Gt, Gte };

    Kind kind = Kind::Equals;
    bool cased = false;       // compare against the raw value instead of the case-folded one
    bool expectExists = true; // Kind::Exists
    Cmp cmp = Cmp::Gt;        // Kind::NumCompare
    double number = 0;        // Kind::NumCompare
    uint32_t cidrNet = 0;     // Kind::Cidr (IPv4, host order)
    uint32_t cidrMask = 0;
    std::string literal;      // folded (or raw when `cased`) text for Equals/Contains/StartsWith/EndsWith
    std::string globChars;    // Kind::Glob: pattern characters ...
    std::string globKinds;    // ... and per-character class: 'c' literal, '?' any one, '*' any run
    std::shared_ptr<const std::regex> regex;

    /// `raw` is the original field value, `folded` its case-folded form.
    bool matches(std::string_view raw, std::string_view folded) const;
};

struct FieldMatcher {
    std::string field;                 // empty = keyword search across all field values
    uint32_t keyId = UINT32_MAX;       // resolved against the event store's string pool before a scan
    bool matchAll = false;             // `|all` modifier: every value must match
    std::vector<ValueMatcher> values;  // otherwise any value may match
};

/// One alternative of a selection: all field matchers must hold (logical AND).
struct SelectionItem {
    std::vector<FieldMatcher> fields;
};

/// A named search identifier from the `detection` section. Alternatives are OR-ed.
struct Selection {
    std::string name;
    std::vector<SelectionItem> alternatives;
};

struct ConditionNode {
    enum class Kind : uint8_t { And, Or, Not, Selection, Quantified };
    Kind kind = Kind::Selection;
    int selection = -1;            // Kind::Selection
    int required = 0;              // Kind::Quantified: 0 = all of, N = at least N of
    std::vector<int> group;        // Kind::Quantified: selection indices
    std::unique_ptr<ConditionNode> left, right;  // Not uses `left` only
};

/// Which events a rule applies to, derived from `logsource`. Empty lists mean "no restriction".
struct LogSourceFilter {
    std::vector<std::string> channels;   // any of (case-insensitive)
    std::vector<uint32_t> eventIds;      // any of
    std::string provider;                // exact provider name, when the category implies one
    std::vector<uint32_t> channelIds;    // resolved pool ids (filled before a scan)
    uint32_t providerId = UINT32_MAX;
    bool resolvable = true;              // false when a required channel/provider is absent from the dataset
};

struct CompiledRule {
    std::string title, id, description, status, author, sourceFile;
    Level level = Level::Medium;
    std::vector<std::string> tags;
    std::string category, product, service;
    LogSourceFilter source;
    std::vector<Selection> selections;
    std::unique_ptr<ConditionNode> condition;
};

struct RuleDiagnostic {
    std::string sourceFile;
    std::string title;
    std::string message;
};

class SigmaRuleCompiler {
public:
    /// Compiles every rule document in `yamlText`. Rules that use unsupported features are skipped
    /// and reported through `diagnostics`; nothing is thrown for bad rules.
    std::vector<CompiledRule> compile(std::string_view yamlText, const std::string& sourceFile,
                                      std::vector<RuleDiagnostic>& diagnostics) const;

    /// Compiles a single parsed rule document. Throws ParseError describing why it cannot be compiled.
    CompiledRule compileRule(const YamlNode& doc, const std::string& sourceFile) const;

    /// Parses a condition expression against the given selection names.
    static std::unique_ptr<ConditionNode> parseCondition(std::string_view expr, const std::vector<Selection>& selections);

private:
    static Selection compileSelection(const std::string& name, const YamlNode& node);
    static SelectionItem compileSelectionMap(const YamlNode& map);
    static FieldMatcher compileField(const std::string& keySpec, const YamlNode& value);
    static LogSourceFilter buildLogSource(const std::string& category, const std::string& product,
                                          const std::string& service);
};

}  // namespace td::sigma
