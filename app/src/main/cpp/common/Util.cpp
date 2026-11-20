// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "common/Util.hpp"

#include <cmath>
#include <cstdio>
#include <ctime>

namespace td {

void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

void utf16leToUtf8(const uint8_t* p, size_t units, std::string& out, bool stopAtNul) {
    out.reserve(out.size() + units);
    for (size_t i = 0; i < units; ++i) {
        uint32_t u = loadLe<uint16_t>(p + i * 2);
        if (u == 0 && stopAtNul) break;
        if (u < 0x80) {
            out.push_back(static_cast<char>(u));
            continue;
        }
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < units) {
            uint32_t lo = loadLe<uint16_t>(p + (i + 1) * 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            } else {
                u = 0xFFFD;
            }
        } else if (u >= 0xD800 && u <= 0xDFFF) {
            u = 0xFFFD;  // unpaired surrogate
        }
        appendUtf8(out, u);
    }
}

namespace {

// Decodes one code point; malformed bytes decode as U+FFFD and advance by one byte.
inline uint32_t decodeUtf8(std::string_view in, size_t& i) {
    const auto b0 = static_cast<uint8_t>(in[i]);
    if (b0 < 0x80) {
        ++i;
        return b0;
    }
    int len = (b0 >= 0xF0 && b0 <= 0xF4) ? 4 : (b0 >= 0xE0) ? 3 : (b0 >= 0xC2 && b0 < 0xE0) ? 2 : 0;
    if (len == 0 || b0 > 0xF4 || i + len > in.size()) {
        ++i;
        return 0xFFFD;
    }
    uint32_t cp = b0 & (0xFF >> (len + 1));
    for (int k = 1; k < len; ++k) {
        const auto b = static_cast<uint8_t>(in[i + k]);
        if ((b & 0xC0) != 0x80) {
            ++i;
            return 0xFFFD;
        }
        cp = (cp << 6) | (b & 0x3F);
    }
    i += len;
    return cp;
}

inline uint32_t foldCodepoint(uint32_t cp) {
    if (cp >= 'A' && cp <= 'Z') return cp + 32;
    if (cp < 0xC0) return cp;
    if (cp >= 0xC0 && cp <= 0xDE && cp != 0xD7) return cp + 32;        // Latin-1
    if (cp >= 0x391 && cp <= 0x3A9 && cp != 0x3A2) return cp + 32;     // Greek
    if (cp >= 0x410 && cp <= 0x42F) return cp + 32;                    // Cyrillic А-Я
    if (cp >= 0x400 && cp <= 0x40F) return cp + 80;                    // Cyrillic Ѐ-Џ (incl. Є, І, Ї)
    if (cp == 0x490) return 0x491;                                     // Ґ
    return cp;
}

}  // namespace

std::u16string utf8ToUtf16(std::string_view in) {
    std::u16string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size();) {
        uint32_t cp = decodeUtf8(in, i);
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
        } else {
            out.push_back(static_cast<char16_t>(cp));
        }
    }
    return out;
}

void foldCaseInto(std::string_view in, std::string& out) {
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size();) {
        const auto b = static_cast<uint8_t>(in[i]);
        if (b < 0x80) {
            out.push_back(static_cast<char>((b >= 'A' && b <= 'Z') ? b + 32 : b));
            ++i;
        } else {
            appendUtf8(out, foldCodepoint(decodeUtf8(in, i)));
        }
    }
}

std::string foldCase(std::string_view in) {
    std::string out;
    foldCaseInto(in, out);
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

bool iequalsAscii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        auto x = static_cast<unsigned char>(a[i]), y = static_cast<unsigned char>(b[i]);
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return false;
    }
    return true;
}

std::string base64Encode(std::string_view bytes) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < bytes.size(); i += 3) {
        const uint32_t v = (static_cast<uint8_t>(bytes[i]) << 16) | (static_cast<uint8_t>(bytes[i + 1]) << 8) |
                           static_cast<uint8_t>(bytes[i + 2]);
        out.push_back(tbl[v >> 18]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back(tbl[v & 63]);
    }
    if (i + 1 == bytes.size()) {
        const uint32_t v = static_cast<uint8_t>(bytes[i]) << 16;
        out.push_back(tbl[v >> 18]);
        out.push_back(tbl[(v >> 12) & 63]);
        out += "==";
    } else if (i + 2 == bytes.size()) {
        const uint32_t v = (static_cast<uint8_t>(bytes[i]) << 16) | (static_cast<uint8_t>(bytes[i + 1]) << 8);
        out.push_back(tbl[v >> 18]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::string hexEncode(const uint8_t* p, size_t n, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = digits[p[i] >> 4];
        out[i * 2 + 1] = digits[p[i] & 15];
    }
    return out;
}

// ---- time ----

namespace {
constexpr uint64_t kFiletimeEpochDiff = 116444736000000000ULL;  // 1601 -> 1970 in 100 ns ticks

// Days since 1970-01-01 for a proleptic Gregorian civil date (Howard Hinnant's algorithm).
int64_t daysFromCivil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void civilFromDays(int64_t z, int& y, unsigned& m, unsigned& d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const auto doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t yy = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y = static_cast<int>(yy + (m <= 2));
}

struct Civil {
    int y;
    unsigned mo, d, h, mi, s;
};

Civil civilFromUnixSeconds(int64_t secs) {
    int64_t days = secs / 86400;
    int64_t rem = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        --days;
    }
    Civil c{};
    civilFromDays(days, c.y, c.mo, c.d);
    c.h = static_cast<unsigned>(rem / 3600);
    c.mi = static_cast<unsigned>((rem % 3600) / 60);
    c.s = static_cast<unsigned>(rem % 60);
    return c;
}
}  // namespace

int64_t filetimeToUnixMs(uint64_t ft) {
    return (static_cast<int64_t>(ft) - static_cast<int64_t>(kFiletimeEpochDiff)) / 10000;
}

std::string formatFiletimeIso(uint64_t ft) {
    const int64_t ticks = static_cast<int64_t>(ft) - static_cast<int64_t>(kFiletimeEpochDiff);
    int64_t secs = ticks / 10000000;
    int64_t frac = ticks % 10000000;
    if (frac < 0) {
        frac += 10000000;
        --secs;
    }
    const Civil c = civilFromUnixSeconds(secs);
    char buf[48];
    std::snprintf(buf, sizeof buf, "%04d-%02u-%02uT%02u:%02u:%02u.%07lldZ", c.y, c.mo, c.d, c.h, c.mi, c.s,
                  static_cast<long long>(frac));
    return buf;
}

std::string formatUnixMs(int64_t ms) {
    int64_t secs = ms / 1000;
    int64_t frac = ms % 1000;
    if (frac < 0) {
        frac += 1000;
        --secs;
    }
    const Civil c = civilFromUnixSeconds(secs);
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04d-%02u-%02u %02u:%02u:%02u.%03lld", c.y, c.mo, c.d, c.h, c.mi, c.s,
                  static_cast<long long>(frac));
    return buf;
}

bool parseTimestampMs(std::string_view s, int64_t& outMs) {
    s = trim(s);
    if (s.size() < 19) return false;
    auto num = [&](size_t pos, size_t len, int& out) {
        int v = 0;
        for (size_t i = 0; i < len; ++i) {
            const char ch = s[pos + i];
            if (ch < '0' || ch > '9') return false;
            v = v * 10 + (ch - '0');
        }
        out = v;
        return true;
    };
    int y, mo, d, h, mi, sec;
    if (!num(0, 4, y) || s[4] != '-' || !num(5, 2, mo) || s[7] != '-' || !num(8, 2, d) ||
        (s[10] != 'T' && s[10] != ' ') || !num(11, 2, h) || s[13] != ':' || !num(14, 2, mi) || s[16] != ':' ||
        !num(17, 2, sec))
        return false;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 60) return false;
    int64_t ms = 0;
    if (s.size() > 20 && s[19] == '.') {
        int digits = 0;
        for (size_t i = 20; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i, ++digits) {
            if (digits < 3) ms = ms * 10 + (s[i] - '0');
        }
        for (; digits < 3; ++digits) ms *= 10;
    }
    outMs = (daysFromCivil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 + h * 3600 + mi * 60 +
             sec) * 1000 + ms;
    return true;
}

// ---- JSON ----

void JsonWriter::comma() {
    if (afterKey_) {
        afterKey_ = false;
        return;
    }
    if (!first_.empty()) {
        if (!first_.back()) out_.push_back(',');
        first_.back() = false;
    }
}

JsonWriter& JsonWriter::beginObject() {
    comma();
    out_.push_back('{');
    first_.push_back(true);
    return *this;
}
JsonWriter& JsonWriter::endObject() {
    out_.push_back('}');
    first_.pop_back();
    return *this;
}
JsonWriter& JsonWriter::beginArray() {
    comma();
    out_.push_back('[');
    first_.push_back(true);
    return *this;
}
JsonWriter& JsonWriter::endArray() {
    out_.push_back(']');
    first_.pop_back();
    return *this;
}

static void jsonEscapeInto(std::string& out, std::string_view v) {
    out.push_back('"');
    for (size_t i = 0; i < v.size();) {
        const auto c = static_cast<unsigned char>(v[i]);
        if (c < 0x80) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof buf, "\\u%04x", c);
                        out += buf;
                    } else {
                        out.push_back(static_cast<char>(c));
                    }
            }
            ++i;
        } else {
            // Re-encode through the validating decoder so the output is always well-formed UTF-8.
            const uint32_t cp = decodeUtf8(v, i);
            appendUtf8(out, cp);
        }
    }
    out.push_back('"');
}

JsonWriter& JsonWriter::key(std::string_view k) {
    comma();
    jsonEscapeInto(out_, k);
    out_.push_back(':');
    afterKey_ = true;
    return *this;
}
JsonWriter& JsonWriter::value(std::string_view v) {
    comma();
    jsonEscapeInto(out_, v);
    return *this;
}
JsonWriter& JsonWriter::value(int64_t v) {
    comma();
    out_ += std::to_string(v);
    return *this;
}
JsonWriter& JsonWriter::value(uint64_t v) {
    comma();
    out_ += std::to_string(v);
    return *this;
}
JsonWriter& JsonWriter::value(double v) {
    comma();
    if (!std::isfinite(v)) {
        out_ += "null";
    } else {
        char buf[32];
        std::snprintf(buf, sizeof buf, "%.6g", v);
        out_ += buf;
    }
    return *this;
}
JsonWriter& JsonWriter::value(bool v) {
    comma();
    out_ += v ? "true" : "false";
    return *this;
}

void ByteWriter::putString(std::string_view s, size_t maxBytes) {
    if (maxBytes > 0xFFFF) maxBytes = 0xFFFF;
    size_t n = s.size();
    if (n > maxBytes) {
        n = maxBytes;
        while (n > 0 && (static_cast<uint8_t>(s[n]) & 0xC0) == 0x80) --n;  // do not split a code point
    }
    put<uint16_t>(static_cast<uint16_t>(n));
    buf_.insert(buf_.end(), s.begin(), s.begin() + static_cast<std::ptrdiff_t>(n));
}

}  // namespace td
