// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Turns the BinXML SAX stream of one event record into a flat, normalised ParsedEvent:
//   <System>     -> provider / channel / computer / EventID / level / TimeCreated
//   <EventData>  -> one field per <Data Name="...">
//   <UserData>   -> one field per leaf element
// and applies Sysmon / Security-Auditing specific normalisation so that both sources expose
// the same field vocabulary (Image, CommandLine, ParentImage, ProcessId, ...).
#pragma once

#include <string>
#include <vector>

#include "evtx/BinXmlDecoder.hpp"
#include "evtx/EvtxMmapReader.hpp"
#include "store/EventStore.hpp"

namespace td::evtx {

class SysmonNormalizer final : public BinXmlVisitor {
public:
    /// Decodes and normalises one record. Returns false (leaving `out` unspecified) when the
    /// record's BinXML is malformed; `error` then holds the reason.
    bool normalize(BinXmlDecoder& decoder, const RecordView& record, ParsedEvent& out, std::string& error);

    void onOpenElement(std::string_view name) override;
    void onAttribute(std::string_view name, std::string_view value) override;
    void onText(std::string_view text) override;
    void onCloseElement(std::string_view name) override;

    /// Sysmon event id -> short human-readable task name ("ProcessCreate", ...); empty when unknown.
    static std::string_view sysmonEventName(uint32_t eventId);

private:
    enum class Section { None, System, EventData, UserData };
    struct Frame {
        std::string name;
        std::string text;
        std::string dataName;
        bool hasChild = false;
    };

    void addField(std::string key, std::string value);
    void finish(const RecordView& record);
    void normalizeSysmon();
    void normalizeSecurity();

    ParsedEvent* ev_ = nullptr;
    std::vector<Frame> stack_;
    Section section_ = Section::None;
    bool timeSet_ = false;
    int unnamedData_ = 0;
};

}  // namespace td::evtx
