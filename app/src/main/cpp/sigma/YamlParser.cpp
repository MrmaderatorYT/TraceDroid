// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "sigma/YamlParser.hpp"

namespace td::sigma {

const YamlNode* YamlNode::get(std::string_view key) const {
    if (type != Type::Mapping) return nullptr;
    for (const auto& e : entries)
        if (e.first == key) return &e.second;
    return nullptr;
}

std::string YamlNode::str(std::string_view key, std::string_view fallback) const {
    const YamlNode* n = get(key);
    return n && n->isScalar() ? n->scalar : std::string(fallback);
}

namespace {

struct Line {
    int indent = 0;
    std::string text;  // content without indentation, comments and trailing whitespace
    int number = 0;
    std::string raw;   // original line (block scalars need untouched content)
};

[[noreturn]] void fail(const Line& l, const std::string& msg) {
    throw ParseError("YAML line " + std::to_string(l.number) + ": " + msg);
}

// Removes a trailing comment: '#' starts a comment at line start or after whitespace, outside quotes.
std::string stripComment(std::string_view s) {
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (quote) {
            if (quote == '"' && c == '\\') ++i;
            else if (c == quote) {
                if (quote == '\'' && i + 1 < s.size() && s[i + 1] == '\'') ++i;
                else quote = 0;
            }
        } else if ((c == '"' || c == '\'') && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t' || s[i - 1] == '[' ||
                                               s[i - 1] == '{' || s[i - 1] == ',' || s[i - 1] == ':')) {
            quote = c;
        } else if (c == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) {
            return std::string(trim(s.substr(0, i)));
        }
    }
    return std::string(trim(s));
}

class Parser {
public:
    explicit Parser(std::string_view text) {
        int number = 0;
        size_t pos = 0;
        while (pos <= text.size()) {
            size_t nl = text.find('\n', pos);
            if (nl == std::string_view::npos) nl = text.size();
            std::string_view raw = text.substr(pos, nl - pos);
            if (!raw.empty() && raw.back() == '\r') raw.remove_suffix(1);
            ++number;
            if (number == 1 && raw.size() >= 3 && raw.substr(0, 3) == "\xEF\xBB\xBF") raw.remove_prefix(3);
            Line l;
            l.number = number;
            l.raw.assign(raw);
            size_t ind = 0;
            while (ind < raw.size() && raw[ind] == ' ') ++ind;
            l.indent = static_cast<int>(ind);
            l.text = stripComment(raw.substr(ind));
            lines_.push_back(std::move(l));
            pos = nl + 1;
        }
    }

    std::vector<YamlNode> parseAll() {
        std::vector<YamlNode> docs;
        while (true) {
            while (cur_ < lines_.size() && lines_[cur_].text.empty()) ++cur_;
            if (cur_ >= lines_.size()) break;
            if (isDocMarker(lines_[cur_], "---")) {
                // "--- " may be followed by inline content; Sigma never does this, so only the bare marker is supported.
                ++cur_;
                continue;
            }
            if (isDocMarker(lines_[cur_], "...")) {
                ++cur_;
                continue;
            }
            docEnd_ = cur_;
            while (docEnd_ < lines_.size() && !isDocMarker(lines_[docEnd_], "---") && !isDocMarker(lines_[docEnd_], "..."))
                ++docEnd_;
            YamlNode doc = parseNode(lines_[cur_].indent);
            skipBlank();
            if (cur_ < docEnd_) fail(lines_[cur_], "unexpected content (bad indentation?)");
            docs.push_back(std::move(doc));
        }
        return docs;
    }

private:
    static bool isDocMarker(const Line& l, std::string_view marker) {
        return l.indent == 0 && l.raw.size() >= 3 && std::string_view(l.raw).substr(0, 3) == marker &&
               (l.raw.size() == 3 || l.raw[3] == ' ');
    }

    void skipBlank() {
        while (cur_ < lines_.size() && cur_ < docEndOrAll() && lines_[cur_].text.empty()) ++cur_;
    }
    size_t docEndOrAll() const { return docEnd_ ? docEnd_ : lines_.size(); }
    bool atEnd() {
        skipBlank();
        return cur_ >= docEndOrAll();
    }

    static bool isSeqItem(const std::string& t) { return !t.empty() && t[0] == '-' && (t.size() == 1 || t[1] == ' '); }

    // Splits "key: rest" when the line is a mapping entry. Handles quoted keys.
    static bool splitKey(const Line& l, std::string& key, std::string& rest) {
        const std::string& t = l.text;
        if (t.empty()) return false;
        size_t colon = std::string::npos;
        if (t[0] == '"' || t[0] == '\'') {
            const char q = t[0];
            size_t i = 1;
            std::string k;
            for (; i < t.size(); ++i) {
                if (q == '"' && t[i] == '\\' && i + 1 < t.size()) {
                    k.push_back(t[++i]);
                } else if (t[i] == q) {
                    if (q == '\'' && i + 1 < t.size() && t[i + 1] == '\'') {
                        k.push_back('\'');
                        ++i;
                    } else {
                        break;
                    }
                } else {
                    k.push_back(t[i]);
                }
            }
            if (i >= t.size()) return false;
            size_t j = i + 1;
            while (j < t.size() && t[j] == ' ') ++j;
            if (j >= t.size() || t[j] != ':' || (j + 1 < t.size() && t[j + 1] != ' ')) return false;
            key = std::move(k);
            colon = j;
        } else {
            if (t[0] == '[' || t[0] == '{') return false;
            for (size_t i = 0; i < t.size(); ++i) {
                if (t[i] == ':' && (i + 1 == t.size() || t[i + 1] == ' ')) {
                    colon = i;
                    break;
                }
            }
            if (colon == std::string::npos) return false;
            key = std::string(trim(std::string_view(t).substr(0, colon)));
        }
        rest = std::string(trim(std::string_view(t).substr(colon + 1)));
        return true;
    }

    YamlNode parseNode(int indent) {
        if (atEnd()) return {};
        Line& l = lines_[cur_];
        if (l.indent < indent) return {};
        if (isSeqItem(l.text)) return parseSequence(l.indent);
        std::string key, rest;
        if (splitKey(l, key, rest)) return parseMapping(l.indent);
        return parseMultilineScalar(l.indent);
    }

    YamlNode parseSequence(int indent) {
        YamlNode seq;
        seq.type = YamlNode::Type::Sequence;
        while (!atEnd()) {
            Line& l = lines_[cur_];
            if (l.indent != indent || !isSeqItem(l.text)) {
                if (l.indent > indent) fail(l, "bad indentation in sequence");
                break;
            }
            // Rewrite "- content" into a virtual line holding just the content at its own column,
            // so nested mappings/sequences inside the item parse with ordinary indentation rules.
            size_t skip = 1;
            while (skip < l.text.size() && l.text[skip] == ' ') ++skip;
            if (skip >= l.text.size()) {
                ++cur_;
                if (!atEnd() && lines_[cur_].indent > indent) seq.items.push_back(parseNode(lines_[cur_].indent));
                else seq.items.emplace_back();
                continue;
            }
            l.indent += static_cast<int>(skip);
            l.text.erase(0, skip);
            seq.items.push_back(parseNode(l.indent));
        }
        return seq;
    }

    YamlNode parseMapping(int indent) {
        YamlNode map;
        map.type = YamlNode::Type::Mapping;
        while (!atEnd()) {
            Line& l = lines_[cur_];
            if (l.indent != indent) {
                if (l.indent > indent) fail(l, "bad indentation in mapping");
                break;
            }
            std::string key, rest;
            if (isSeqItem(l.text) || !splitKey(l, key, rest)) break;
            ++cur_;
            YamlNode value;
            if (rest.empty()) {
                if (!atEnd()) {
                    const Line& next = lines_[cur_];
                    // A sequence may sit at the same column as its parent key.
                    if (next.indent > indent || (next.indent == indent && isSeqItem(next.text)))
                        value = parseNode(next.indent);
                }
            } else {
                value = parseInlineValue(rest, indent, l);
            }
            map.entries.emplace_back(std::move(key), std::move(value));
        }
        return map;
    }

    YamlNode parseMultilineScalar(int indent) {
        // A plain (or quoted) scalar standing alone, possibly continued on deeper/equal lines.
        const Line first = lines_[cur_];
        ++cur_;
        return parseInlineValue(first.text, indent - 1, first);
    }

    // Parses a value that starts on the same line as its key (or sequence dash).
    YamlNode parseInlineValue(std::string rest, int parentIndent, const Line& origin) {
        const char c = rest[0];
        if (c == '|' || c == '>') return parseBlockScalar(rest, parentIndent, origin);
        if (c == '[' || c == '{') {
            // Flow collections may span lines: keep appending until brackets balance.
            while (!flowBalanced(rest)) {
                if (cur_ >= docEndOrAll()) fail(origin, "unterminated flow collection");
                rest.push_back(' ');
                rest += lines_[cur_].text;
                ++cur_;
            }
            size_t pos = 0;
            YamlNode n = parseFlow(rest, pos, origin);
            if (!trim(std::string_view(rest).substr(pos)).empty()) fail(origin, "trailing characters after flow collection");
            return n;
        }
        if (c == '&' || c == '*' || (c == '!' && rest.size() > 1 && rest[1] != ' '))
            fail(origin, "anchors, aliases and tags are not supported");
        if (c == '"' || c == '\'') {
            // Quoted scalars may also span lines.
            while (!quoteClosed(rest)) {
                if (cur_ >= docEndOrAll()) fail(origin, "unterminated quoted scalar");
                rest.push_back(' ');
                rest += std::string(trim(lines_[cur_].raw));
                ++cur_;
            }
            size_t pos = 0;
            YamlNode n = parseQuoted(rest, pos, origin);
            if (!trim(std::string_view(rest).substr(pos)).empty()) fail(origin, "trailing characters after quoted scalar");
            return n;
        }
        // Plain scalar; continuation lines are more indented than the parent and are folded with spaces.
        while (cur_ < docEndOrAll()) {
            const Line& next = lines_[cur_];
            if (next.text.empty()) {
                // Blank line inside a plain scalar only counts if the scalar continues after it.
                size_t k = cur_ + 1;
                while (k < docEndOrAll() && lines_[k].text.empty()) ++k;
                if (k >= docEndOrAll() || lines_[k].indent <= parentIndent) break;
                cur_ = k;
                continue;
            }
            if (next.indent <= parentIndent) break;
            rest.push_back(' ');
            rest += next.text;
            ++cur_;
        }
        return plainScalar(rest);
    }

    static YamlNode plainScalar(std::string_view s) {
        YamlNode n;
        s = trim(s);
        if (s.empty() || s == "~" || s == "null" || s == "Null" || s == "NULL") return n;
        n.type = YamlNode::Type::Scalar;
        n.scalar.assign(s);
        return n;
    }

    static bool flowBalanced(const std::string& s) {
        int depth = 0;
        char quote = 0;
        for (size_t i = 0; i < s.size(); ++i) {
            const char c = s[i];
            if (quote) {
                if (quote == '"' && c == '\\') ++i;
                else if (c == quote) quote = 0;
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '[' || c == '{') {
                ++depth;
            } else if (c == ']' || c == '}') {
                --depth;
            }
        }
        return depth <= 0 && !quote;
    }

    static bool quoteClosed(const std::string& s) {
        const char q = s[0];
        for (size_t i = 1; i < s.size(); ++i) {
            if (q == '"' && s[i] == '\\') {
                ++i;
            } else if (s[i] == q) {
                if (q == '\'' && i + 1 < s.size() && s[i + 1] == '\'') ++i;
                else return true;
            }
        }
        return false;
    }

    YamlNode parseQuoted(const std::string& s, size_t& pos, const Line& origin) {
        const char q = s[pos++];
        YamlNode n;
        n.type = YamlNode::Type::Scalar;
        n.quoted = true;
        while (pos < s.size()) {
            const char c = s[pos++];
            if (q == '\'') {
                if (c == '\'') {
                    if (pos < s.size() && s[pos] == '\'') {
                        n.scalar.push_back('\'');
                        ++pos;
                    } else {
                        return n;
                    }
                } else {
                    n.scalar.push_back(c);
                }
                continue;
            }
            if (c == '"') return n;
            if (c != '\\') {
                n.scalar.push_back(c);
                continue;
            }
            if (pos >= s.size()) break;
            const char e = s[pos++];
            switch (e) {
                case 'n': n.scalar.push_back('\n'); break;
                case 't': n.scalar.push_back('\t'); break;
                case 'r': n.scalar.push_back('\r'); break;
                case '0': n.scalar.push_back('\0'); break;
                case 'a': n.scalar.push_back('\a'); break;
                case 'b': n.scalar.push_back('\b'); break;
                case 'e': n.scalar.push_back('\x1b'); break;
                case 'f': n.scalar.push_back('\f'); break;
                case 'v': n.scalar.push_back('\v'); break;
                case ' ': n.scalar.push_back(' '); break;
                case '/': n.scalar.push_back('/'); break;
                case 'x':
                case 'u':
                case 'U': {
                    const int digits = e == 'x' ? 2 : e == 'u' ? 4 : 8;
                    uint32_t cp = 0;
                    for (int i = 0; i < digits; ++i) {
                        if (pos >= s.size()) fail(origin, "truncated escape sequence");
                        const char h = s[pos++];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= static_cast<uint32_t>(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= static_cast<uint32_t>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= static_cast<uint32_t>(h - 'A' + 10);
                        else fail(origin, "invalid hex digit in escape sequence");
                    }
                    if (e == 'x') n.scalar.push_back(static_cast<char>(cp));
                    else appendUtf8(n.scalar, cp);
                    break;
                }
                default: n.scalar.push_back(e); break;  // \\ \" and unknown escapes
            }
        }
        fail(origin, "unterminated quoted scalar");
    }

    static void skipSpaces(const std::string& s, size_t& pos) {
        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
    }

    YamlNode parseFlow(const std::string& s, size_t& pos, const Line& origin) {
        skipSpaces(s, pos);
        if (pos >= s.size()) fail(origin, "unexpected end of flow collection");
        const char c = s[pos];
        if (c == '[') {
            ++pos;
            YamlNode seq;
            seq.type = YamlNode::Type::Sequence;
            for (;;) {
                skipSpaces(s, pos);
                if (pos >= s.size()) fail(origin, "unterminated flow sequence");
                if (s[pos] == ']') {
                    ++pos;
                    return seq;
                }
                seq.items.push_back(parseFlow(s, pos, origin));
                skipSpaces(s, pos);
                if (pos < s.size() && s[pos] == ',') ++pos;
                else if (pos < s.size() && s[pos] != ']') fail(origin, "expected ',' or ']' in flow sequence");
            }
        }
        if (c == '{') {
            ++pos;
            YamlNode map;
            map.type = YamlNode::Type::Mapping;
            for (;;) {
                skipSpaces(s, pos);
                if (pos >= s.size()) fail(origin, "unterminated flow mapping");
                if (s[pos] == '}') {
                    ++pos;
                    return map;
                }
                YamlNode key = parseFlowScalar(s, pos, origin, true);
                skipSpaces(s, pos);
                if (pos >= s.size() || s[pos] != ':') fail(origin, "expected ':' in flow mapping");
                ++pos;
                map.entries.emplace_back(key.scalar, parseFlow(s, pos, origin));
                skipSpaces(s, pos);
                if (pos < s.size() && s[pos] == ',') ++pos;
                else if (pos < s.size() && s[pos] != '}') fail(origin, "expected ',' or '}' in flow mapping");
            }
        }
        return parseFlowScalar(s, pos, origin, false);
    }

    YamlNode parseFlowScalar(const std::string& s, size_t& pos, const Line& origin, bool isKey) {
        skipSpaces(s, pos);
        if (pos < s.size() && (s[pos] == '"' || s[pos] == '\'')) return parseQuoted(s, pos, origin);
        const size_t start = pos;
        while (pos < s.size()) {
            const char c = s[pos];
            if (c == ',' || c == ']' || c == '}') break;
            if (isKey && c == ':' && (pos + 1 >= s.size() || s[pos + 1] == ' ')) break;
            ++pos;
        }
        return plainScalar(std::string_view(s).substr(start, pos - start));
    }

    YamlNode parseBlockScalar(const std::string& header, int parentIndent, const Line& origin) {
        const bool literal = header[0] == '|';
        char chomp = 'c';  // clip
        int explicitIndent = 0;
        for (size_t i = 1; i < header.size(); ++i) {
            const char c = header[i];
            if (c == '-' || c == '+') chomp = c;
            else if (c >= '1' && c <= '9') explicitIndent = c - '0';
            else fail(origin, "invalid block scalar header");
        }
        // Content indentation: explicit, or that of the first non-blank line.
        int blockIndent = explicitIndent ? parentIndent + explicitIndent : -1;
        std::vector<std::string> content;
        while (cur_ < docEndOrAll()) {
            const Line& l = lines_[cur_];
            const bool blank = trim(l.raw).empty();
            size_t rawIndent = 0;
            while (rawIndent < l.raw.size() && l.raw[rawIndent] == ' ') ++rawIndent;
            if (!blank) {
                if (blockIndent < 0) {
                    if (static_cast<int>(rawIndent) <= parentIndent) break;
                    blockIndent = static_cast<int>(rawIndent);
                }
                if (static_cast<int>(rawIndent) < blockIndent) break;
                content.push_back(l.raw.substr(static_cast<size_t>(blockIndent)));
            } else {
                content.emplace_back();
            }
            ++cur_;
        }
        size_t trailingBlank = 0;
        while (!content.empty() && content.back().empty()) {
            content.pop_back();
            ++trailingBlank;
        }
        YamlNode n;
        n.type = YamlNode::Type::Scalar;
        n.quoted = true;
        for (size_t i = 0; i < content.size(); ++i) {
            n.scalar += content[i];
            if (i + 1 == content.size()) break;
            if (literal) {
                n.scalar.push_back('\n');
            } else if (content[i + 1].empty()) {
                // Folded style: each blank line is a paragraph break.
                size_t k = i + 1;
                while (k < content.size() && content[k].empty()) {
                    n.scalar.push_back('\n');
                    ++k;
                }
                i = k - 1;
            } else {
                n.scalar.push_back(' ');
            }
        }
        if (!content.empty() && chomp != '-') n.scalar.push_back('\n');
        if (chomp == '+') n.scalar.append(trailingBlank, '\n');
        return n;
    }

    std::vector<Line> lines_;
    size_t cur_ = 0;
    size_t docEnd_ = 0;
};

}  // namespace

std::vector<YamlNode> parseYaml(std::string_view text) { return Parser(text).parseAll(); }

}  // namespace td::sigma
