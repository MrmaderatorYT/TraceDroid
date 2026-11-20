// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Dependency-free YAML reader covering the subset used by Sigma rules: block mappings and
// sequences, flow sequences/mappings, plain / single- / double-quoted scalars, literal (|) and
// folded (>) block scalars, comments and multi-document streams. Anchors, aliases and tags are
// not part of the Sigma specification and are rejected.
#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/Util.hpp"

namespace td::sigma {

struct YamlNode {
    enum class Type { Null, Scalar, Sequence, Mapping };
    Type type = Type::Null;
    std::string scalar;
    bool quoted = false;  // scalar was written with quotes (so "null"/"~" are strings, not null)
    std::vector<YamlNode> items;
    std::vector<std::pair<std::string, YamlNode>> entries;  // insertion-ordered

    bool isNull() const { return type == Type::Null; }
    bool isScalar() const { return type == Type::Scalar; }
    bool isSequence() const { return type == Type::Sequence; }
    bool isMapping() const { return type == Type::Mapping; }
    /// Mapping lookup; returns nullptr when absent or when this node is not a mapping.
    const YamlNode* get(std::string_view key) const;
    /// Scalar text of a mapping entry, or `fallback`.
    std::string str(std::string_view key, std::string_view fallback = {}) const;
};

/// Parses every document in `text`. Throws ParseError with a line number on malformed input.
std::vector<YamlNode> parseYaml(std::string_view text);

}  // namespace td::sigma
