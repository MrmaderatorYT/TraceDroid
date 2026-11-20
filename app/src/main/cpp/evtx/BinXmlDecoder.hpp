// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Streaming decoder for the Binary XML encoding used inside EVTX records.
// The decoder walks the token stream in place (inside the mmap'd chunk), resolves
// chunk-relative name strings, expands template instances with their substitution
// arrays, recurses into embedded BinXML values, and reports SAX-style events.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "common/Util.hpp"

namespace td::evtx {

/// SAX-style sink. String views are only valid for the duration of the call.
class BinXmlVisitor {
public:
    virtual ~BinXmlVisitor() = default;
    virtual void onOpenElement(std::string_view name) = 0;
    virtual void onAttribute(std::string_view name, std::string_view value) = 0;
    /// Character data; may be delivered in several pieces for one element.
    virtual void onText(std::string_view text) = 0;
    virtual void onCloseElement(std::string_view name) = 0;
};

/// BinXML value types (MS-EVEN6 2.2.12 "BinXml type"). 0x80 marks an array of the base type.
enum class ValueType : uint8_t {
    Null = 0x00,
    String = 0x01,
    AnsiString = 0x02,
    Int8 = 0x03,
    UInt8 = 0x04,
    Int16 = 0x05,
    UInt16 = 0x06,
    Int32 = 0x07,
    UInt32 = 0x08,
    Int64 = 0x09,
    UInt64 = 0x0A,
    Real32 = 0x0B,
    Real64 = 0x0C,
    Bool = 0x0D,
    Binary = 0x0E,
    Guid = 0x0F,
    SizeT = 0x10,
    FileTime = 0x11,
    SysTime = 0x12,
    Sid = 0x13,
    HexInt32 = 0x14,
    HexInt64 = 0x15,
    EvtHandle = 0x20,
    BinXml = 0x21,
    EvtXml = 0x23,
};
inline constexpr uint8_t kArrayFlag = 0x80;

/// One decoder per chunk: name strings are cached by their chunk offset, so records that share
/// the chunk's string table do not re-decode UTF-16 names.
class BinXmlDecoder {
public:
    explicit BinXmlDecoder(std::span<const uint8_t> chunk);

    /// Decodes the BinXML fragment at [offset, offset + size) (chunk-relative).
    /// Throws ParseError when the token stream is malformed or leaves the chunk.
    void decode(uint32_t offset, uint32_t size, BinXmlVisitor& visitor);

    /// Formats a typed BinXML value as text, exactly as it would appear in rendered event XML.
    static void renderValue(uint8_t type, const uint8_t* data, size_t size, std::string& out);

private:
    struct Substitution {
        uint32_t offset;
        uint16_t size;
        uint8_t type;
    };
    using Subs = std::vector<Substitution>;

    uint32_t parseFragment(uint32_t pos, uint32_t end, const Subs* subs, BinXmlVisitor& v, int depth);
    uint32_t parseTemplateInstance(uint32_t pos, uint32_t end, BinXmlVisitor& v, int depth);
    uint32_t parseElement(uint32_t pos, uint32_t end, const Subs* subs, BinXmlVisitor& v, int depth);
    /// Parses value-ish tokens (text, substitutions, char/entity refs) into `out`.
    /// Returns false when the token at `pos` is not a content token.
    bool parseAttributeContent(uint32_t& pos, uint32_t end, const Subs* subs, std::string& out, bool& sawNonNull);
    void emitSubstitution(uint16_t index, uint8_t declaredType, const Subs* subs, BinXmlVisitor& v, int depth);

    const std::string& nameAt(uint32_t offset);
    /// If the name structure is stored inline at `pos`, returns the position just past it.
    uint32_t skipInlineName(uint32_t nameOffset, uint32_t pos) const;

    void need(uint32_t pos, uint32_t n, uint32_t end) const {
        if (pos > end || n > end - pos) throw ParseError("BinXML: truncated token stream");
    }
    uint8_t u8(uint32_t pos) const { return chunk_[pos]; }
    uint16_t u16(uint32_t pos) const { return loadLe<uint16_t>(chunk_.data() + pos); }
    uint32_t u32(uint32_t pos) const { return loadLe<uint32_t>(chunk_.data() + pos); }

    std::span<const uint8_t> chunk_;
    std::unordered_map<uint32_t, std::string> names_;
    std::string scratch_;
};

/// Visitor that renders the event as indented XML text (used for the raw-record inspector).
class XmlRenderVisitor final : public BinXmlVisitor {
public:
    void onOpenElement(std::string_view name) override;
    void onAttribute(std::string_view name, std::string_view value) override;
    void onText(std::string_view text) override;
    void onCloseElement(std::string_view name) override;
    std::string take();

private:
    void closePendingTag();
    static void escapeInto(std::string& out, std::string_view s, bool attribute);
    std::string out_;
    int depth_ = 0;
    bool tagOpen_ = false;    // "<name attr=..." emitted but not yet ">"
    bool lastWasClose_ = false;  // previous output was a closing tag (controls indentation)
};

}  // namespace td::evtx
