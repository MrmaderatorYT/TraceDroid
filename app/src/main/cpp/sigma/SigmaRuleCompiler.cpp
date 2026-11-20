// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "sigma/SigmaRuleCompiler.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>

namespace td::sigma {

std::string_view levelName(Level l) {
    switch (l) {
        case Level::Informational: return "informational";
        case Level::Low: return "low";
        case Level::Medium: return "medium";
        case Level::High: return "high";
        case Level::Critical: return "critical";
        default: return "none";
    }
}

namespace {

Level parseLevel(std::string_view s) {
    const std::string f = foldCase(trim(s));
    if (f == "informational" || f == "info") return Level::Informational;
    if (f == "low") return Level::Low;
    if (f == "medium") return Level::Medium;
    if (f == "high") return Level::High;
    if (f == "critical") return Level::Critical;
    return Level::Medium;  // the specification's default when the attribute is missing or unknown
}

bool parseIpv4(std::string_view s, uint32_t& out) {
    uint32_t value = 0;
    int parts = 0;
    while (parts < 4) {
        unsigned octet = 0;
        const auto res = std::from_chars(s.data(), s.data() + s.size(), octet);
        if (res.ec != std::errc() || octet > 255) return false;
        value = (value << 8) | octet;
        ++parts;
        s.remove_prefix(static_cast<size_t>(res.ptr - s.data()));
        if (parts < 4) {
            if (s.empty() || s[0] != '.') return false;
            s.remove_prefix(1);
        }
    }
    if (!s.empty()) return false;
    out = value;
    return true;
}

bool globMatch(std::string_view chars, std::string_view kinds, std::string_view v) {
    size_t p = 0, s = 0, star = std::string_view::npos, mark = 0;
    const size_t n = chars.size();
    while (s < v.size()) {
        if (p < n && (kinds[p] == '?' || (kinds[p] == 'c' && chars[p] == v[s]))) {
            ++p;
            ++s;
        } else if (p < n && kinds[p] == '*') {
            star = p++;
            mark = s;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            s = ++mark;
        } else {
            return false;
        }
    }
    while (p < n && kinds[p] == '*') ++p;
    return p == n;
}

struct RawValue {
    std::string text;
    bool isNull = false;
    bool cased = false;      // transformed bytes (base64 / wide) must be compared verbatim
    bool wildcards = true;   // `*` and `?` keep their Sigma meaning
};

/// Builds a glob-family matcher from a Sigma string value.
ValueMatcher makeStringMatcher(const RawValue& rv, bool prefixStar, bool suffixStar, bool forceCased) {
    struct Segment {
        char kind;  // 'c', '?', '*'
        std::string text;
    };
    std::vector<Segment> segs;
    auto literal = [&](char c) {
        if (segs.empty() || segs.back().kind != 'c') segs.push_back({'c', {}});
        segs.back().text.push_back(c);
    };
    auto star = [&] {
        if (segs.empty() || segs.back().kind != '*') segs.push_back({'*', {}});
    };
    if (prefixStar) star();
    const std::string& s = rv.text;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (!rv.wildcards) {
            literal(c);
        } else if (c == '\\' && i + 1 < s.size() && (s[i + 1] == '*' || s[i + 1] == '?' || s[i + 1] == '\\')) {
            literal(s[++i]);  // escaped wildcard or escaped backslash
        } else if (c == '*') {
            star();
        } else if (c == '?') {
            segs.push_back({'?', {}});
        } else {
            literal(c);
        }
    }
    if (suffixStar) star();

    ValueMatcher m;
    m.cased = rv.cased || forceCased;
    if (!m.cased)
        for (auto& seg : segs)
            if (seg.kind == 'c') seg.text = foldCase(seg.text);

    auto isLit = [&](size_t i) { return segs[i].kind == 'c'; };
    auto isStar = [&](size_t i) { return segs[i].kind == '*'; };
    if (segs.empty()) {
        m.kind = ValueMatcher::Kind::Equals;
    } else if (segs.size() == 1 && isLit(0)) {
        m.kind = ValueMatcher::Kind::Equals;
        m.literal = segs[0].text;
    } else if (segs.size() == 1 && isStar(0)) {
        m.kind = ValueMatcher::Kind::Contains;  // lone "*": any present value
    } else if (segs.size() == 2 && isLit(0) && isStar(1)) {
        m.kind = ValueMatcher::Kind::StartsWith;
        m.literal = segs[0].text;
    } else if (segs.size() == 2 && isStar(0) && isLit(1)) {
        m.kind = ValueMatcher::Kind::EndsWith;
        m.literal = segs[1].text;
    } else if (segs.size() == 3 && isStar(0) && isLit(1) && isStar(2)) {
        m.kind = ValueMatcher::Kind::Contains;
        m.literal = segs[1].text;
    } else {
        m.kind = ValueMatcher::Kind::Glob;
        for (const auto& seg : segs) {
            if (seg.kind == 'c') {
                m.globChars += seg.text;
                m.globKinds.append(seg.text.size(), 'c');
            } else {
                m.globChars.push_back(seg.kind);
                m.globKinds.push_back(seg.kind);
            }
        }
    }
    return m;
}

std::string toUtf16Bytes(std::string_view utf8, bool bigEndian, bool bom) {
    std::string out;
    if (bom) out += bigEndian ? "\xFE\xFF" : "\xFF\xFE";
    for (const char16_t u : utf8ToUtf16(utf8)) {
        const char lo = static_cast<char>(u & 0xFF), hi = static_cast<char>(u >> 8);
        if (bigEndian) {
            out.push_back(hi);
            out.push_back(lo);
        } else {
            out.push_back(lo);
            out.push_back(hi);
        }
    }
    return out;
}

void replaceAll(std::string& s, std::string_view from, std::string_view to) {
    for (size_t pos = 0; (pos = s.find(from, pos)) != std::string::npos; pos += to.size()) s.replace(pos, from.size(), to);
}

std::vector<std::string> splitModifiers(const std::string& keySpec, std::string& field) {
    std::vector<std::string> mods;
    size_t start = 0;
    bool first = true;
    while (start <= keySpec.size()) {
        size_t bar = keySpec.find('|', start);
        if (bar == std::string::npos) bar = keySpec.size();
        std::string part(trim(std::string_view(keySpec).substr(start, bar - start)));
        if (first) field = std::move(part);
        else mods.push_back(foldCase(part));
        first = false;
        start = bar + 1;
    }
    return mods;
}

struct LogSourceEntry {
    std::string_view name;
    std::vector<std::string_view> channels;
    std::vector<uint32_t> eventIds;
};

const std::string_view kSysmon = "Microsoft-Windows-Sysmon/Operational";

const std::vector<LogSourceEntry>& serviceTable() {
    static const std::vector<LogSourceEntry> table = {
        {"sysmon", {kSysmon}, {}},
        {"security", {"Security"}, {}},
        {"system", {"System"}, {}},
        {"application", {"Application"}, {}},
        {"powershell", {"Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational"}, {}},
        {"powershell-classic", {"Windows PowerShell"}, {}},
        {"windefend", {"Microsoft-Windows-Windows Defender/Operational"}, {}},
        {"taskscheduler", {"Microsoft-Windows-TaskScheduler/Operational"}, {}},
        {"wmi", {"Microsoft-Windows-WMI-Activity/Operational"}, {}},
        {"dns-server", {"DNS Server"}, {}},
        {"dns-server-analytic", {"Microsoft-Windows-DNS-Server/Analytical"}, {}},
        {"dns-client", {"Microsoft-Windows-DNS Client Events/Operational"}, {}},
        {"firewall-as", {"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"}, {}},
        {"bits-client", {"Microsoft-Windows-Bits-Client/Operational"}, {}},
        {"applocker",
         {"Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL",
          "Microsoft-Windows-AppLocker/Packaged app-Deployment", "Microsoft-Windows-AppLocker/Packaged app-Execution"},
         {}},
        {"ntlm", {"Microsoft-Windows-NTLM/Operational"}, {}},
        {"smbclient-security", {"Microsoft-Windows-SmbClient/Security"}, {}},
        {"smbclient-connectivity", {"Microsoft-Windows-SmbClient/Connectivity"}, {}},
        {"terminalservices-localsessionmanager", {"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"}, {}},
        {"codeintegrity-operational", {"Microsoft-Windows-CodeIntegrity/Operational"}, {}},
        {"driver-framework", {"Microsoft-Windows-DriverFrameworks-UserMode/Operational"}, {}},
        {"msexchange-management", {"MSExchange Management"}, {}},
        {"printservice-admin", {"Microsoft-Windows-PrintService/Admin"}, {}},
        {"printservice-operational", {"Microsoft-Windows-PrintService/Operational"}, {}},
        {"security-mitigations",
         {"Microsoft-Windows-Security-Mitigations/Kernel Mode", "Microsoft-Windows-Security-Mitigations/User Mode"}, {}},
        {"shell-core", {"Microsoft-Windows-Shell-Core/Operational"}, {}},
        {"openssh", {"OpenSSH/Operational"}, {}},
        {"ldap_debug", {"Microsoft-Windows-LDAP-Client/Debug"}, {}},
        {"appxdeployment-server", {"Microsoft-Windows-AppXDeploymentServer/Operational"}, {}},
        {"appxpackaging-om", {"Microsoft-Windows-AppxPackaging/Operational"}, {}},
        {"lsa-server", {"Microsoft-Windows-LSA/Operational"}, {}},
        {"diagnosis-scripted", {"Microsoft-Windows-Diagnosis-Scripted/Operational"}, {}},
        {"vhdmp", {"Microsoft-Windows-VHDMP/Operational"}, {}},
        {"capi2", {"Microsoft-Windows-CAPI2/Operational"}, {}},
        {"certificateservicesclient-lifecycle-system",
         {"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"}, {}},
        {"kernel-event-tracing", {"Microsoft-Windows-Kernel-EventTracing"}, {}},
        {"microsoft-servicebus-client", {"Microsoft-ServiceBus-Client"}, {}},
    };
    return table;
}

const std::vector<LogSourceEntry>& categoryTable() {
    static const std::string_view ps = "Microsoft-Windows-PowerShell/Operational";
    static const std::string_view psCore = "PowerShellCore/Operational";
    static const std::string_view psClassic = "Windows PowerShell";
    static const std::vector<LogSourceEntry> table = {
        // Sysmon 1 and Security 4688 are both normalised to the process_creation field vocabulary.
        {"process_creation", {kSysmon, "Security"}, {1, 4688}},
        {"file_change", {kSysmon}, {2}},
        {"network_connection", {kSysmon}, {3}},
        {"sysmon_status", {kSysmon}, {4, 16}},
        {"process_termination", {kSysmon}, {5}},
        {"driver_load", {kSysmon}, {6}},
        {"image_load", {kSysmon}, {7}},
        {"create_remote_thread", {kSysmon}, {8}},
        {"raw_access_thread", {kSysmon}, {9}},
        {"process_access", {kSysmon}, {10}},
        {"file_event", {kSysmon}, {11}},
        {"registry_add", {kSysmon}, {12}},
        {"registry_delete", {kSysmon}, {12}},
        {"registry_set", {kSysmon}, {13}},
        {"registry_rename", {kSysmon}, {14}},
        {"registry_event", {kSysmon}, {12, 13, 14}},
        {"create_stream_hash", {kSysmon}, {15}},
        {"pipe_created", {kSysmon}, {17, 18}},
        {"wmi_event", {kSysmon}, {19, 20, 21}},
        {"dns_query", {kSysmon}, {22}},
        {"file_delete", {kSysmon}, {23, 26}},
        {"file_delete_detected", {kSysmon}, {26}},
        {"clipboard_capture", {kSysmon}, {24}},
        {"process_tampering", {kSysmon}, {25}},
        {"file_block_executable", {kSysmon}, {27}},
        {"file_block_shredding", {kSysmon}, {28}},
        {"file_executable_detected", {kSysmon}, {29}},
        {"sysmon_error", {kSysmon}, {255}},
        {"ps_module", {ps, psCore}, {4103}},
        {"ps_script", {ps, psCore}, {4104}},
        {"ps_classic_start", {psClassic}, {400}},
        {"ps_classic_provider_start", {psClassic}, {600}},
        {"ps_classic_script", {psClassic}, {800}},
    };
    return table;
}

const LogSourceEntry* findEntry(const std::vector<LogSourceEntry>& table, std::string_view name) {
    for (const auto& e : table)
        if (e.name == name) return &e;
    return nullptr;
}

// ---- condition parsing ----

struct CondParser {
    std::vector<std::string> tokens;
    size_t pos = 0;
    const std::vector<Selection>& selections;

    bool atEnd() const { return pos >= tokens.size(); }
    bool peekIs(std::string_view kw) const { return !atEnd() && iequalsAscii(tokens[pos], kw); }

    int findSelection(std::string_view name) const {
        for (size_t i = 0; i < selections.size(); ++i)
            if (selections[i].name == name) return static_cast<int>(i);
        return -1;
    }

    static bool nameMatches(std::string_view pattern, std::string_view name) {
        std::string kinds(pattern.size(), 'c');
        for (size_t i = 0; i < pattern.size(); ++i)
            if (pattern[i] == '*') kinds[i] = '*';
        return globMatch(pattern, kinds, name);
    }

    std::unique_ptr<ConditionNode> parseOr() {
        auto left = parseAnd();
        while (peekIs("or")) {
            ++pos;
            auto node = std::make_unique<ConditionNode>();
            node->kind = ConditionNode::Kind::Or;
            node->left = std::move(left);
            node->right = parseAnd();
            left = std::move(node);
        }
        return left;
    }

    std::unique_ptr<ConditionNode> parseAnd() {
        auto left = parseNot();
        while (peekIs("and")) {
            ++pos;
            auto node = std::make_unique<ConditionNode>();
            node->kind = ConditionNode::Kind::And;
            node->left = std::move(left);
            node->right = parseNot();
            left = std::move(node);
        }
        return left;
    }

    std::unique_ptr<ConditionNode> parseNot() {
        if (peekIs("not")) {
            ++pos;
            auto node = std::make_unique<ConditionNode>();
            node->kind = ConditionNode::Kind::Not;
            node->left = parseNot();
            return node;
        }
        return parsePrimary();
    }

    std::unique_ptr<ConditionNode> parsePrimary() {
        if (atEnd()) throw ParseError("condition ends unexpectedly");
        const std::string tok = tokens[pos];
        if (tok == "(") {
            ++pos;
            auto inner = parseOr();
            if (atEnd() || tokens[pos] != ")") throw ParseError("condition: missing ')'");
            ++pos;
            return inner;
        }
        if (tok == ")") throw ParseError("condition: unexpected ')'");

        // Quantifier: "1 of x*", "all of them", "any of sel_*", "2 of (a, b)" is not part of the spec.
        if (pos + 1 < tokens.size() && iequalsAscii(tokens[pos + 1], "of")) {
            int required;
            if (iequalsAscii(tok, "all")) {
                required = 0;
            } else if (iequalsAscii(tok, "any")) {
                required = 1;
            } else {
                unsigned n = 0;
                const auto res = std::from_chars(tok.data(), tok.data() + tok.size(), n);
                if (res.ec != std::errc() || res.ptr != tok.data() + tok.size() || n == 0)
                    throw ParseError("condition: invalid quantifier '" + tok + "'");
                required = static_cast<int>(n);
            }
            pos += 2;
            if (atEnd()) throw ParseError("condition: quantifier without a target");
            const std::string target = tokens[pos++];
            auto node = std::make_unique<ConditionNode>();
            node->kind = ConditionNode::Kind::Quantified;
            node->required = required;
            for (size_t i = 0; i < selections.size(); ++i) {
                const std::string& name = selections[i].name;
                const bool hit = iequalsAscii(target, "them") ? (name.empty() || name[0] != '_') : nameMatches(target, name);
                if (hit) node->group.push_back(static_cast<int>(i));
            }
            if (node->group.empty()) throw ParseError("condition: '" + target + "' matches no selection");
            return node;
        }

        const int idx = findSelection(tok);
        if (idx < 0) throw ParseError("condition references unknown selection '" + tok + "'");
        ++pos;
        auto node = std::make_unique<ConditionNode>();
        node->kind = ConditionNode::Kind::Selection;
        node->selection = idx;
        return node;
    }
};

}  // namespace

// ---------------------------------------------------------------- ValueMatcher

bool ValueMatcher::matches(std::string_view raw, std::string_view folded) const {
    const std::string_view v = cased ? raw : folded;
    switch (kind) {
        case Kind::Equals: return v == literal;
        case Kind::Contains: return literal.empty() || v.find(literal) != std::string_view::npos;
        case Kind::StartsWith: return v.starts_with(literal);
        case Kind::EndsWith: return v.ends_with(literal);
        case Kind::Glob: return globMatch(globChars, globKinds, v);
        case Kind::Regex: return std::regex_search(raw.begin(), raw.end(), *regex);
        case Kind::IsNull: return raw.empty();
        case Kind::Exists: return expectExists;
        case Kind::NumCompare: {
            const std::string tmp(trim(raw));
            char* end = nullptr;
            const double d = std::strtod(tmp.c_str(), &end);
            if (tmp.empty() || end != tmp.c_str() + tmp.size()) return false;
            switch (cmp) {
                case Cmp::Lt: return d < number;
                case Cmp::Lte: return d <= number;
                case Cmp::Gt: return d > number;
                default: return d >= number;
            }
        }
        case Kind::Cidr: {
            uint32_t ip = 0;
            return parseIpv4(trim(raw), ip) && (ip & cidrMask) == cidrNet;
        }
    }
    return false;
}

// ---------------------------------------------------------------- compiler

FieldMatcher SigmaRuleCompiler::compileField(const std::string& keySpec, const YamlNode& value) {
    FieldMatcher fm;
    const std::vector<std::string> mods = splitModifiers(keySpec, fm.field);

    std::vector<RawValue> values;
    auto addScalar = [&](const YamlNode& n) {
        if (n.isNull()) values.push_back({{}, true, false, true});
        else if (n.isScalar()) values.push_back({n.scalar, false, false, true});
        else throw ParseError("field '" + keySpec + "': nested structures are not valid field values");
    };
    if (value.isSequence()) {
        for (const auto& item : value.items) addScalar(item);
        if (values.empty()) throw ParseError("field '" + keySpec + "': empty value list");
    } else {
        addScalar(value);
    }

    enum class Mode { Plain, Contains, StartsWith, EndsWith, Regex, Cidr, Exists, Lt, Lte, Gt, Gte };
    Mode mode = fm.field.empty() ? Mode::Contains : Mode::Plain;  // keywords are substring searches
    bool forceCased = false, reIgnoreCase = false, reMultiline = false;

    for (const std::string& mod : mods) {
        if (mod == "contains") mode = Mode::Contains;
        else if (mod == "startswith") mode = Mode::StartsWith;
        else if (mod == "endswith") mode = Mode::EndsWith;
        else if (mod == "all") fm.matchAll = true;
        else if (mod == "re") mode = Mode::Regex;
        else if (mod == "i" && mode == Mode::Regex) reIgnoreCase = true;
        else if (mod == "m" && mode == Mode::Regex) reMultiline = true;
        else if (mod == "s" && mode == Mode::Regex) { /* dot-all is not expressible in ECMAScript; '.' rarely needs it for single-line fields */ }
        else if (mod == "cased") forceCased = true;
        else if (mod == "cidr") mode = Mode::Cidr;
        else if (mod == "exists") mode = Mode::Exists;
        else if (mod == "lt") mode = Mode::Lt;
        else if (mod == "lte") mode = Mode::Lte;
        else if (mod == "gt") mode = Mode::Gt;
        else if (mod == "gte") mode = Mode::Gte;
        else if (mod == "base64") {
            for (auto& v : values) {
                if (v.isNull) continue;
                v.text = base64Encode(v.text);
                v.cased = true;
                v.wildcards = false;
            }
        } else if (mod == "base64offset") {
            // A value embedded in a base64 stream appears in one of three alignments.
            static constexpr size_t startTrim[3] = {0, 2, 3};
            static constexpr size_t endTrim[3] = {0, 3, 2};
            std::vector<RawValue> expanded;
            for (const auto& v : values) {
                if (v.isNull) continue;
                for (size_t shift = 0; shift < 3; ++shift) {
                    const std::string enc = base64Encode(std::string(shift, ' ') + v.text);
                    const size_t cut = endTrim[(v.text.size() + shift) % 3];
                    if (enc.size() <= startTrim[shift] + cut) continue;
                    expanded.push_back({enc.substr(startTrim[shift], enc.size() - startTrim[shift] - cut), false, true, false});
                }
            }
            values = std::move(expanded);
        } else if (mod == "wide" || mod == "utf16le" || mod == "utf16be" || mod == "utf16") {
            for (auto& v : values) {
                if (v.isNull) continue;
                v.text = toUtf16Bytes(v.text, mod == "utf16be", mod == "utf16");
                v.cased = true;
                v.wildcards = false;
            }
        } else if (mod == "windash") {
            // Windows accepts several dash-like characters as option prefixes.
            static const std::string_view dashes[] = {"/", "\xE2\x80\x93", "\xE2\x80\x94", "\xE2\x80\x95"};
            std::vector<RawValue> expanded;
            for (const auto& v : values) {
                expanded.push_back(v);
                if (v.isNull || v.text.find('-') == std::string::npos) continue;
                for (const auto dash : dashes) {
                    RawValue alt = v;
                    replaceAll(alt.text, " -", std::string(" ") + std::string(dash));
                    if (!alt.text.empty() && alt.text[0] == '-') alt.text.replace(0, 1, dash);
                    if (alt.text != v.text) expanded.push_back(std::move(alt));
                }
            }
            values = std::move(expanded);
        } else {
            throw ParseError("field '" + keySpec + "': unsupported modifier '" + mod + "'");
        }
    }

    for (const RawValue& v : values) {
        ValueMatcher m;
        if (mode == Mode::Exists) {
            const std::string f = foldCase(v.text);
            m.kind = ValueMatcher::Kind::Exists;
            m.expectExists = !(v.isNull || f == "false" || f == "no" || f == "0");
        } else if (v.isNull) {
            m.kind = ValueMatcher::Kind::IsNull;
        } else if (mode == Mode::Regex) {
            std::string pattern = v.text;
            bool icase = reIgnoreCase;
            if (pattern.rfind("(?i)", 0) == 0) {
                pattern.erase(0, 4);
                icase = true;
            }
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (icase) flags |= std::regex::icase;
            if (reMultiline) flags |= std::regex::multiline;
            try {
                m.regex = std::make_shared<const std::regex>(pattern, flags);
            } catch (const std::regex_error& e) {
                throw ParseError("field '" + keySpec + "': regular expression not supported by the engine (" + e.what() + ")");
            }
            m.kind = ValueMatcher::Kind::Regex;
        } else if (mode == Mode::Cidr) {
            const size_t slash = v.text.find('/');
            uint32_t net = 0;
            unsigned bits = 32;
            const std::string_view addr = std::string_view(v.text).substr(0, slash);
            if (slash != std::string::npos) {
                const std::string_view b = std::string_view(v.text).substr(slash + 1);
                const auto res = std::from_chars(b.data(), b.data() + b.size(), bits);
                if (res.ec != std::errc() || bits > 32) bits = 255;
            }
            m.kind = ValueMatcher::Kind::Cidr;
            if (bits <= 32 && parseIpv4(trim(addr), net)) {
                m.cidrMask = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
                m.cidrNet = net & m.cidrMask;
            } else {
                // IPv6 (or malformed) networks never match the IPv4 comparison.
                m.cidrMask = 0xFFFFFFFFu;
                m.cidrNet = 0;
                if (v.text.find(':') == std::string::npos)
                    throw ParseError("field '" + keySpec + "': invalid CIDR network '" + v.text + "'");
                m.cidrMask = 0;
                m.cidrNet = 1;  // (ip & 0) == 1 is never true
            }
        } else if (mode == Mode::Lt || mode == Mode::Lte || mode == Mode::Gt || mode == Mode::Gte) {
            char* end = nullptr;
            m.number = std::strtod(v.text.c_str(), &end);
            if (v.text.empty() || end != v.text.c_str() + v.text.size())
                throw ParseError("field '" + keySpec + "': numeric comparison needs a number");
            m.kind = ValueMatcher::Kind::NumCompare;
            m.cmp = mode == Mode::Lt ? ValueMatcher::Cmp::Lt
                    : mode == Mode::Lte ? ValueMatcher::Cmp::Lte
                    : mode == Mode::Gt ? ValueMatcher::Cmp::Gt : ValueMatcher::Cmp::Gte;
        } else {
            const bool pre = mode == Mode::Contains || mode == Mode::EndsWith;
            const bool post = mode == Mode::Contains || mode == Mode::StartsWith;
            m = makeStringMatcher(v, pre, post, forceCased);
        }
        fm.values.push_back(std::move(m));
    }
    if (fm.values.empty()) throw ParseError("field '" + keySpec + "': no usable values");
    return fm;
}

SelectionItem SigmaRuleCompiler::compileSelectionMap(const YamlNode& map) {
    SelectionItem item;
    for (const auto& [key, value] : map.entries) item.fields.push_back(compileField(key, value));
    if (item.fields.empty()) throw ParseError("empty selection");
    return item;
}

Selection SigmaRuleCompiler::compileSelection(const std::string& name, const YamlNode& node) {
    Selection sel;
    sel.name = name;
    if (node.isMapping()) {
        sel.alternatives.push_back(compileSelectionMap(node));
    } else if (node.isSequence()) {
        YamlNode keywords;
        keywords.type = YamlNode::Type::Sequence;
        for (const auto& item : node.items) {
            if (item.isMapping()) sel.alternatives.push_back(compileSelectionMap(item));
            else if (item.isScalar()) keywords.items.push_back(item);
            else throw ParseError("selection '" + name + "': unsupported list item");
        }
        if (!keywords.items.empty()) {
            SelectionItem kw;
            kw.fields.push_back(compileField("", keywords));
            sel.alternatives.push_back(std::move(kw));
        }
    } else if (node.isScalar()) {
        SelectionItem kw;
        kw.fields.push_back(compileField("", node));
        sel.alternatives.push_back(std::move(kw));
    }
    if (sel.alternatives.empty()) throw ParseError("selection '" + name + "' is empty");
    return sel;
}

std::unique_ptr<ConditionNode> SigmaRuleCompiler::parseCondition(std::string_view expr,
                                                                 const std::vector<Selection>& selections) {
    CondParser parser{{}, 0, selections};
    std::string cur;
    auto flush = [&] {
        if (!cur.empty()) parser.tokens.push_back(std::move(cur));
        cur.clear();
    };
    for (const char c : expr) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            flush();
        } else if (c == '(' || c == ')') {
            flush();
            parser.tokens.emplace_back(1, c);
        } else if (c == '|') {
            throw ParseError("aggregation expressions ('| count() ...') are not supported");
        } else {
            cur.push_back(c);
        }
    }
    flush();
    if (parser.tokens.empty()) throw ParseError("empty condition");
    auto root = parser.parseOr();
    if (!parser.atEnd()) throw ParseError("condition: unexpected token '" + parser.tokens[parser.pos] + "'");
    return root;
}

LogSourceFilter SigmaRuleCompiler::buildLogSource(const std::string& categoryIn, const std::string& productIn,
                                                  const std::string& serviceIn) {
    const std::string category = foldCase(categoryIn), product = foldCase(productIn), service = foldCase(serviceIn);
    if (!product.empty() && product != "windows")
        throw ParseError("logsource product '" + productIn + "' does not apply to Windows event logs");

    LogSourceFilter f;
    if (!category.empty()) {
        const LogSourceEntry* e = findEntry(categoryTable(), category);
        if (!e) throw ParseError("logsource category '" + categoryIn + "' has no EVTX mapping");
        for (const auto c : e->channels) f.channels.emplace_back(c);
        f.eventIds = e->eventIds;
    }
    if (!service.empty()) {
        const LogSourceEntry* e = findEntry(serviceTable(), service);
        if (!e) throw ParseError("logsource service '" + serviceIn + "' has no EVTX channel mapping");
        f.channels.clear();  // an explicit service narrows the category's default channels
        for (const auto c : e->channels) f.channels.emplace_back(c);
    }
    if (category.empty() && service.empty() && product.empty())
        throw ParseError("rule has no usable logsource");
    return f;
}

CompiledRule SigmaRuleCompiler::compileRule(const YamlNode& doc, const std::string& sourceFile) const {
    if (!doc.isMapping()) throw ParseError("rule document is not a mapping");
    if (doc.get("action")) throw ParseError("rule collections ('action: global/repeat') are not supported");
    if (doc.get("correlation")) throw ParseError("correlation rules are not supported");

    CompiledRule rule;
    rule.sourceFile = sourceFile;
    rule.title = doc.str("title");
    if (rule.title.empty()) throw ParseError("rule has no title");
    rule.id = doc.str("id");
    rule.description = doc.str("description");
    rule.status = doc.str("status");
    rule.author = doc.str("author");
    rule.level = parseLevel(doc.str("level", "medium"));
    if (const YamlNode* tags = doc.get("tags"); tags && tags->isSequence())
        for (const auto& t : tags->items)
            if (t.isScalar()) rule.tags.push_back(t.scalar);

    const YamlNode* logsource = doc.get("logsource");
    if (!logsource || !logsource->isMapping()) throw ParseError("rule has no logsource");
    rule.category = logsource->str("category");
    rule.product = logsource->str("product");
    rule.service = logsource->str("service");
    rule.source = buildLogSource(rule.category, rule.product, rule.service);

    const YamlNode* detection = doc.get("detection");
    if (!detection || !detection->isMapping()) throw ParseError("rule has no detection section");
    const YamlNode* condition = nullptr;
    for (const auto& [name, node] : detection->entries) {
        if (name == "condition") condition = &node;
        else if (name == "timeframe") continue;
        else rule.selections.push_back(compileSelection(name, node));
    }
    if (!condition) throw ParseError("detection has no condition");

    if (condition->isScalar()) {
        rule.condition = parseCondition(condition->scalar, rule.selections);
    } else if (condition->isSequence() && !condition->items.empty()) {
        // A list of conditions is a logical OR of its members.
        for (const auto& item : condition->items) {
            if (!item.isScalar()) throw ParseError("condition list contains a non-string entry");
            auto part = parseCondition(item.scalar, rule.selections);
            if (!rule.condition) {
                rule.condition = std::move(part);
            } else {
                auto node = std::make_unique<ConditionNode>();
                node->kind = ConditionNode::Kind::Or;
                node->left = std::move(rule.condition);
                node->right = std::move(part);
                rule.condition = std::move(node);
            }
        }
    } else {
        throw ParseError("condition must be a string or a list of strings");
    }
    return rule;
}

std::vector<CompiledRule> SigmaRuleCompiler::compile(std::string_view yamlText, const std::string& sourceFile,
                                                     std::vector<RuleDiagnostic>& diagnostics) const {
    std::vector<CompiledRule> rules;
    std::vector<YamlNode> docs;
    try {
        docs = parseYaml(yamlText);
    } catch (const ParseError& e) {
        diagnostics.push_back({sourceFile, {}, e.what()});
        return rules;
    }
    for (const YamlNode& doc : docs) {
        if (!doc.isMapping()) continue;
        try {
            rules.push_back(compileRule(doc, sourceFile));
        } catch (const ParseError& e) {
            diagnostics.push_back({sourceFile, doc.str("title"), e.what()});
        }
    }
    return rules;
}

}  // namespace td::sigma
