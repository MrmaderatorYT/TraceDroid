// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "evtx/BinXmlDecoder.hpp"

#include <cstdio>

namespace td::evtx {

namespace {

// BinXML tokens. Bit 0x40 on a token means "more data follows" (attributes present / more attributes).
enum Token : uint8_t {
    kEof = 0x00,
    kOpenStartElement = 0x01,
    kCloseStartElement = 0x02,
    kCloseEmptyElement = 0x03,
    kEndElement = 0x04,
    kValueText = 0x05,
    kAttribute = 0x06,
    kCData = 0x07,
    kCharRef = 0x08,
    kEntityRef = 0x09,
    kPiTarget = 0x0A,
    kPiData = 0x0B,
    kTemplateInstance = 0x0C,
    kNormalSubstitution = 0x0D,
    kOptionalSubstitution = 0x0E,
    kFragmentHeader = 0x0F,
};
constexpr uint8_t kMoreFlag = 0x40;
constexpr int kMaxDepth = 64;
constexpr uint32_t kTemplateDefHeader = 24;  // next offset (4) + GUID (16) + data size (4)
constexpr uint32_t kNameHeader = 8;          // next offset (4) + hash (2) + char count (2)

size_t fixedElementSize(uint8_t base) {
    switch (static_cast<ValueType>(base)) {
        case ValueType::Int8:
        case ValueType::UInt8: return 1;
        case ValueType::Int16:
        case ValueType::UInt16: return 2;
        case ValueType::Int32:
        case ValueType::UInt32:
        case ValueType::Real32:
        case ValueType::Bool:
        case ValueType::HexInt32: return 4;
        case ValueType::Int64:
        case ValueType::UInt64:
        case ValueType::Real64:
        case ValueType::FileTime:
        case ValueType::HexInt64: return 8;
        case ValueType::Guid:
        case ValueType::SysTime: return 16;
        default: return 0;
    }
}

void appendFmt(std::string& out, const char* fmt, auto... args) {
    char buf[96];
    const int n = std::snprintf(buf, sizeof buf, fmt, args...);
    if (n > 0) out.append(buf, static_cast<size_t>(n) < sizeof buf ? static_cast<size_t>(n) : sizeof buf - 1);
}

void appendEntity(std::string& out, std::string_view name) {
    if (name == "amp") out.push_back('&');
    else if (name == "lt") out.push_back('<');
    else if (name == "gt") out.push_back('>');
    else if (name == "quot") out.push_back('"');
    else if (name == "apos") out.push_back('\'');
    else {
        out.push_back('&');
        out.append(name);
        out.push_back(';');
    }
}

}  // namespace

BinXmlDecoder::BinXmlDecoder(std::span<const uint8_t> chunk) : chunk_(chunk) { names_.reserve(128); }

void BinXmlDecoder::decode(uint32_t offset, uint32_t size, BinXmlVisitor& visitor) {
    if (offset > chunk_.size() || size > chunk_.size() - offset) throw ParseError("BinXML: fragment outside chunk");
    parseFragment(offset, offset + size, nullptr, visitor, 0);
}

const std::string& BinXmlDecoder::nameAt(uint32_t offset) {
    if (const auto it = names_.find(offset); it != names_.end()) return it->second;
    if (offset > chunk_.size() || kNameHeader > chunk_.size() - offset) throw ParseError("BinXML: name offset outside chunk");
    const uint32_t chars = u16(offset + 6);
    if (chars * 2 > chunk_.size() - offset - kNameHeader) throw ParseError("BinXML: name string outside chunk");
    std::string name;
    utf16leToUtf8(chunk_.data() + offset + kNameHeader, chars, name);
    return names_.emplace(offset, std::move(name)).first->second;
}

uint32_t BinXmlDecoder::skipInlineName(uint32_t nameOffset, uint32_t pos) const {
    if (nameOffset != pos) return pos;  // defined elsewhere in the chunk (string table hit)
    if (kNameHeader > chunk_.size() - pos) throw ParseError("BinXML: inline name outside chunk");
    return pos + kNameHeader + static_cast<uint32_t>(u16(pos + 6)) * 2 + 2;  // + UTF-16 NUL terminator
}

uint32_t BinXmlDecoder::parseFragment(uint32_t pos, uint32_t end, const Subs* subs, BinXmlVisitor& v, int depth) {
    if (depth > kMaxDepth) throw ParseError("BinXML: nesting too deep");
    while (pos < end) {
        const uint8_t tok = u8(pos);
        switch (tok & ~kMoreFlag) {
            case kFragmentHeader:
                need(pos, 4, end);  // token, major, minor, flags
                pos += 4;
                break;
            case kTemplateInstance:
                pos = parseTemplateInstance(pos, end, v, depth);
                break;
            case kOpenStartElement:
                pos = parseElement(pos, end, subs, v, depth);
                break;
            case kEof:
                return pos + 1;
            default:
                throw ParseError("BinXML: unexpected token at fragment level");
        }
    }
    return pos;
}

uint32_t BinXmlDecoder::parseTemplateInstance(uint32_t pos, uint32_t end, BinXmlVisitor& v, int depth) {
    // token(1) unknown(1) template-id(4) definition-offset(4)
    need(pos, 10, end);
    const uint32_t defOffset = u32(pos + 6);
    pos += 10;

    if (defOffset > chunk_.size() || kTemplateDefHeader > chunk_.size() - defOffset)
        throw ParseError("BinXML: template definition outside chunk");
    const uint32_t bodySize = u32(defOffset + 20);
    const uint32_t bodyStart = defOffset + kTemplateDefHeader;
    if (bodySize > chunk_.size() - bodyStart) throw ParseError("BinXML: template body outside chunk");
    // The first instance of a template in a chunk carries the definition inline; later
    // instances only reference it by offset.
    if (defOffset == pos) pos = bodyStart + bodySize;

    need(pos, 4, end);
    const uint32_t count = u32(pos);
    pos += 4;
    if (count > (end - pos) / 4) throw ParseError("BinXML: substitution array outside record");

    Subs subs;
    subs.reserve(count);
    uint32_t valuePos = pos + count * 4;
    for (uint32_t i = 0; i < count; ++i) {
        const uint16_t size = u16(pos + i * 4);
        const uint8_t type = u8(pos + i * 4 + 2);
        if (size > end - valuePos) throw ParseError("BinXML: substitution value outside record");
        subs.push_back({valuePos, size, type});
        valuePos += size;
    }

    parseFragment(bodyStart, bodyStart + bodySize, &subs, v, depth + 1);
    return valuePos;
}

bool BinXmlDecoder::parseAttributeContent(uint32_t& pos, uint32_t end, const Subs* subs, std::string& out,
                                          bool& sawNonNull) {
    need(pos, 1, end);
    switch (u8(pos) & ~kMoreFlag) {
        case kValueText: {
            need(pos, 4, end);
            if (u8(pos + 1) != static_cast<uint8_t>(ValueType::String)) throw ParseError("BinXML: non-string value text");
            const uint32_t chars = u16(pos + 2);
            need(pos + 4, chars * 2, end);
            utf16leToUtf8(chunk_.data() + pos + 4, chars, out);
            pos += 4 + chars * 2;
            sawNonNull = true;
            return true;
        }
        case kNormalSubstitution:
        case kOptionalSubstitution: {
            need(pos, 4, end);
            const uint16_t index = u16(pos + 1);
            pos += 4;
            if (subs && index < subs->size()) {
                const Substitution& s = (*subs)[index];
                if (s.type != static_cast<uint8_t>(ValueType::Null) && s.size > 0) {
                    renderValue(s.type, chunk_.data() + s.offset, s.size, out);
                    sawNonNull = true;
                }
            }
            return true;
        }
        case kCharRef: {
            need(pos, 3, end);
            appendUtf8(out, u16(pos + 1));
            pos += 3;
            sawNonNull = true;
            return true;
        }
        case kEntityRef: {
            need(pos, 5, end);
            const uint32_t nameOffset = u32(pos + 1);
            pos = skipInlineName(nameOffset, pos + 5);
            appendEntity(out, nameAt(nameOffset));
            sawNonNull = true;
            return true;
        }
        default:
            return false;
    }
}

void BinXmlDecoder::emitSubstitution(uint16_t index, uint8_t /*declaredType*/, const Subs* subs, BinXmlVisitor& v,
                                     int depth) {
    if (!subs || index >= subs->size()) return;
    const Substitution s = (*subs)[index];  // the value descriptor's type is authoritative
    if (s.type == static_cast<uint8_t>(ValueType::Null) || s.size == 0) return;
    if (s.type == static_cast<uint8_t>(ValueType::BinXml)) {
        // Embedded fragment (typically <EventData>/<UserData>) with its own template instance.
        parseFragment(s.offset, s.offset + s.size, nullptr, v, depth + 1);
        return;
    }
    std::string text;
    renderValue(s.type, chunk_.data() + s.offset, s.size, text);
    if (!text.empty()) v.onText(text);
}

uint32_t BinXmlDecoder::parseElement(uint32_t pos, uint32_t end, const Subs* subs, BinXmlVisitor& v, int depth) {
    if (depth > kMaxDepth) throw ParseError("BinXML: nesting too deep");
    // token(1) dependency-id(2) data-size(4) name-offset(4) [attribute-list-size(4)]
    need(pos, 11, end);
    const bool hasAttributes = (u8(pos) & kMoreFlag) != 0;
    const uint32_t nameOffset = u32(pos + 7);
    pos = skipInlineName(nameOffset, pos + 11);
    const std::string name = nameAt(nameOffset);  // copy: the cache may rehash while children are parsed
    if (hasAttributes) {
        need(pos, 4, end);
        pos += 4;
    }
    v.onOpenElement(name);

    // ---- start tag: attributes until CloseStartElement / CloseEmptyElement ----
    for (;;) {
        need(pos, 1, end);
        const uint8_t tok = u8(pos) & ~kMoreFlag;
        if (tok == kAttribute) {
            need(pos, 5, end);
            const uint32_t attrNameOffset = u32(pos + 1);
            pos = skipInlineName(attrNameOffset, pos + 5);
            std::string value;
            bool sawNonNull = false, sawAny = false;
            while (pos < end && parseAttributeContent(pos, end, subs, value, sawNonNull)) sawAny = true;
            // An attribute whose only content is a null (optional) substitution is omitted.
            if (!sawAny || sawNonNull) v.onAttribute(nameAt(attrNameOffset), value);
        } else if (tok == kCloseStartElement) {
            ++pos;
            break;
        } else if (tok == kCloseEmptyElement) {
            v.onCloseElement(name);
            return pos + 1;
        } else {
            throw ParseError("BinXML: unexpected token in start tag");
        }
    }

    // ---- content until EndElement ----
    for (;;) {
        need(pos, 1, end);
        const uint8_t tok = u8(pos) & ~kMoreFlag;
        switch (tok) {
            case kOpenStartElement:
                pos = parseElement(pos, end, subs, v, depth + 1);
                break;
            case kEndElement:
                v.onCloseElement(name);
                return pos + 1;
            case kValueText:
            case kCharRef:
            case kEntityRef: {
                scratch_.clear();
                bool ignored = false;
                std::string text;
                parseAttributeContent(pos, end, subs, text, ignored);
                if (!text.empty()) v.onText(text);
                break;
            }
            case kNormalSubstitution:
            case kOptionalSubstitution: {
                need(pos, 4, end);
                const uint16_t index = u16(pos + 1);
                const uint8_t type = u8(pos + 3);
                pos += 4;
                emitSubstitution(index, type, subs, v, depth);
                break;
            }
            case kCData: {
                need(pos, 3, end);
                const uint32_t chars = u16(pos + 1);
                need(pos + 3, chars * 2, end);
                std::string text;
                utf16leToUtf8(chunk_.data() + pos + 3, chars, text);
                pos += 3 + chars * 2;
                if (!text.empty()) v.onText(text);
                break;
            }
            case kPiTarget: {
                need(pos, 5, end);
                pos = skipInlineName(u32(pos + 1), pos + 5);
                break;
            }
            case kPiData: {
                need(pos, 3, end);
                const uint32_t chars = u16(pos + 1);
                need(pos + 3, chars * 2, end);
                pos += 3 + chars * 2;
                break;
            }
            case kTemplateInstance:
                pos = parseTemplateInstance(pos, end, v, depth);
                break;
            case kEof:
                // Truncated template body: close what we opened rather than reading past it.
                v.onCloseElement(name);
                return pos;
            default:
                throw ParseError("BinXML: unexpected token in element content");
        }
    }
}

// ---------------------------------------------------------------- value rendering

static void renderScalar(uint8_t base, const uint8_t* d, size_t size, std::string& out) {
    switch (static_cast<ValueType>(base)) {
        case ValueType::Null:
            break;
        case ValueType::String:
        case ValueType::EvtXml:
            utf16leToUtf8(d, size / 2, out);
            break;
        case ValueType::AnsiString:
            for (size_t i = 0; i < size && d[i] != 0; ++i) appendUtf8(out, d[i]);
            break;
        case ValueType::Int8:
            if (size >= 1) appendFmt(out, "%d", static_cast<int>(static_cast<int8_t>(d[0])));
            break;
        case ValueType::UInt8:
            if (size >= 1) appendFmt(out, "%u", static_cast<unsigned>(d[0]));
            break;
        case ValueType::Int16:
            if (size >= 2) appendFmt(out, "%d", static_cast<int>(loadLe<int16_t>(d)));
            break;
        case ValueType::UInt16:
            if (size >= 2) appendFmt(out, "%u", static_cast<unsigned>(loadLe<uint16_t>(d)));
            break;
        case ValueType::Int32:
            if (size >= 4) appendFmt(out, "%d", loadLe<int32_t>(d));
            break;
        case ValueType::UInt32:
            if (size >= 4) appendFmt(out, "%u", loadLe<uint32_t>(d));
            break;
        case ValueType::Int64:
            if (size >= 8) appendFmt(out, "%lld", static_cast<long long>(loadLe<int64_t>(d)));
            break;
        case ValueType::UInt64:
            if (size >= 8) appendFmt(out, "%llu", static_cast<unsigned long long>(loadLe<uint64_t>(d)));
            break;
        case ValueType::Real32:
            if (size >= 4) appendFmt(out, "%g", static_cast<double>(loadLe<float>(d)));
            break;
        case ValueType::Real64:
            if (size >= 8) appendFmt(out, "%g", loadLe<double>(d));
            break;
        case ValueType::Bool: {
            const uint32_t b = size >= 4 ? loadLe<uint32_t>(d) : (size >= 1 ? d[0] : 0);
            out += b ? "true" : "false";
            break;
        }
        case ValueType::Binary:
            out += hexEncode(d, size);
            break;
        case ValueType::Guid:
            if (size >= 16)
                appendFmt(out, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", loadLe<uint32_t>(d),
                          static_cast<unsigned>(loadLe<uint16_t>(d + 4)), static_cast<unsigned>(loadLe<uint16_t>(d + 6)),
                          d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
            break;
        case ValueType::SizeT:
            if (size >= 8) appendFmt(out, "0x%llx", static_cast<unsigned long long>(loadLe<uint64_t>(d)));
            else if (size >= 4) appendFmt(out, "0x%x", loadLe<uint32_t>(d));
            break;
        case ValueType::FileTime:
            if (size >= 8) out += formatFiletimeIso(loadLe<uint64_t>(d));
            break;
        case ValueType::SysTime:
            if (size >= 16)
                appendFmt(out, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", static_cast<unsigned>(loadLe<uint16_t>(d)),
                          static_cast<unsigned>(loadLe<uint16_t>(d + 2)), static_cast<unsigned>(loadLe<uint16_t>(d + 6)),
                          static_cast<unsigned>(loadLe<uint16_t>(d + 8)), static_cast<unsigned>(loadLe<uint16_t>(d + 10)),
                          static_cast<unsigned>(loadLe<uint16_t>(d + 12)), static_cast<unsigned>(loadLe<uint16_t>(d + 14)));
            break;
        case ValueType::Sid: {
            if (size < 8) break;
            const unsigned subCount = d[1];
            uint64_t authority = 0;
            for (int i = 0; i < 6; ++i) authority = (authority << 8) | d[2 + i];  // big-endian
            appendFmt(out, "S-%u-%llu", static_cast<unsigned>(d[0]), static_cast<unsigned long long>(authority));
            for (unsigned i = 0; i < subCount && 8 + (i + 1) * 4 <= size; ++i)
                appendFmt(out, "-%u", loadLe<uint32_t>(d + 8 + i * 4));
            break;
        }
        case ValueType::HexInt32:
            if (size >= 4) appendFmt(out, "0x%x", loadLe<uint32_t>(d));
            break;
        case ValueType::HexInt64:
            if (size >= 8) appendFmt(out, "0x%llx", static_cast<unsigned long long>(loadLe<uint64_t>(d)));
            break;
        case ValueType::EvtHandle:
        case ValueType::BinXml:
            break;  // not representable as attribute/inline text
        default:
            out += hexEncode(d, size);
            break;
    }
}

void BinXmlDecoder::renderValue(uint8_t type, const uint8_t* data, size_t size, std::string& out) {
    if (!(type & kArrayFlag)) {
        renderScalar(type, data, size, out);
        return;
    }
    const uint8_t base = type & ~kArrayFlag;
    bool first = true;
    auto separator = [&] {
        if (!first) out += ", ";
        first = false;
    };
    if (base == static_cast<uint8_t>(ValueType::String)) {
        // Sequence of NUL-terminated UTF-16 strings.
        size_t start = 0;
        const size_t units = size / 2;
        for (size_t i = 0; i <= units; ++i) {
            if (i == units || loadLe<uint16_t>(data + i * 2) == 0) {
                if (i > start) {
                    separator();
                    utf16leToUtf8(data + start * 2, i - start, out);
                }
                start = i + 1;
            }
        }
        return;
    }
    if (base == static_cast<uint8_t>(ValueType::Sid)) {
        for (size_t off = 0; off + 8 <= size;) {
            const size_t len = 8 + static_cast<size_t>(data[off + 1]) * 4;
            if (off + len > size) break;
            separator();
            renderScalar(base, data + off, len, out);
            off += len;
        }
        return;
    }
    const size_t elem = fixedElementSize(base);
    if (elem == 0) {
        renderScalar(base, data, size, out);
        return;
    }
    for (size_t off = 0; off + elem <= size; off += elem) {
        separator();
        renderScalar(base, data + off, elem, out);
    }
}

// ---------------------------------------------------------------- XML rendering

void XmlRenderVisitor::escapeInto(std::string& out, std::string_view s, bool attribute) {
    for (const char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"':
                if (attribute) out += "&quot;";
                else out.push_back(c);
                break;
            default: out.push_back(c);
        }
    }
}

void XmlRenderVisitor::closePendingTag() {
    if (tagOpen_) {
        out_.push_back('>');
        tagOpen_ = false;
    }
}

void XmlRenderVisitor::onOpenElement(std::string_view name) {
    closePendingTag();
    if (!out_.empty()) out_.push_back('\n');
    out_.append(static_cast<size_t>(depth_) * 2, ' ');
    out_.push_back('<');
    out_.append(name);
    tagOpen_ = true;
    lastWasClose_ = false;
    ++depth_;
}

void XmlRenderVisitor::onAttribute(std::string_view name, std::string_view value) {
    out_.push_back(' ');
    out_.append(name);
    out_ += "=\"";
    escapeInto(out_, value, true);
    out_.push_back('"');
}

void XmlRenderVisitor::onText(std::string_view text) {
    closePendingTag();
    escapeInto(out_, text, false);
    lastWasClose_ = false;
}

void XmlRenderVisitor::onCloseElement(std::string_view name) {
    --depth_;
    if (tagOpen_) {
        out_ += "/>";
        tagOpen_ = false;
    } else {
        if (lastWasClose_) {
            out_.push_back('\n');
            out_.append(static_cast<size_t>(depth_) * 2, ' ');
        }
        out_ += "</";
        out_.append(name);
        out_.push_back('>');
    }
    lastWasClose_ = true;
}

std::string XmlRenderVisitor::take() { return std::move(out_); }

}  // namespace td::evtx
