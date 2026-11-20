// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
#include "evtx/SysmonNormalizer.hpp"

#include <algorithm>
#include <charconv>

namespace td::evtx {

namespace {

bool parseUInt(std::string_view s, uint64_t& out) {
    s = trim(s);
    if (s.empty()) return false;
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
        base = 16;
    }
    const auto res = std::from_chars(s.data(), s.data() + s.size(), out, base);
    return res.ec == std::errc() && res.ptr == s.data() + s.size();
}

}  // namespace

std::string_view SysmonNormalizer::sysmonEventName(uint32_t id) {
    switch (id) {
        case 1: return "ProcessCreate";
        case 2: return "FileCreateTime";
        case 3: return "NetworkConnect";
        case 4: return "ServiceStateChange";
        case 5: return "ProcessTerminate";
        case 6: return "DriverLoad";
        case 7: return "ImageLoad";
        case 8: return "CreateRemoteThread";
        case 9: return "RawAccessRead";
        case 10: return "ProcessAccess";
        case 11: return "FileCreate";
        case 12: return "RegistryAddDelete";
        case 13: return "RegistrySetValue";
        case 14: return "RegistryRename";
        case 15: return "FileCreateStreamHash";
        case 16: return "ConfigChange";
        case 17: return "PipeCreated";
        case 18: return "PipeConnected";
        case 19: return "WmiFilter";
        case 20: return "WmiConsumer";
        case 21: return "WmiBinding";
        case 22: return "DnsQuery";
        case 23: return "FileDelete";
        case 24: return "ClipboardChange";
        case 25: return "ProcessTampering";
        case 26: return "FileDeleteDetected";
        case 27: return "FileBlockExecutable";
        case 28: return "FileBlockShredding";
        case 29: return "FileExecutableDetected";
        case 255: return "SysmonError";
        default: return {};
    }
}

bool SysmonNormalizer::normalize(BinXmlDecoder& decoder, const RecordView& record, ParsedEvent& out,
                                 std::string& error) {
    out.clear();
    ev_ = &out;
    stack_.clear();
    section_ = Section::None;
    timeSet_ = false;
    unnamedData_ = 0;
    try {
        decoder.decode(record.binXmlOffset, record.binXmlSize, *this);
    } catch (const ParseError& e) {
        error = e.what();
        return false;
    }
    finish(record);
    return true;
}

void SysmonNormalizer::addField(std::string key, std::string value) {
    ev_->fields.emplace_back(std::move(key), std::move(value));
}

void SysmonNormalizer::onOpenElement(std::string_view name) {
    if (!stack_.empty()) stack_.back().hasChild = true;
    if (stack_.size() == 1) {  // direct child of <Event>
        if (name == "System") section_ = Section::System;
        else if (name == "EventData") section_ = Section::EventData;
        else if (name == "UserData") section_ = Section::UserData;
        else section_ = Section::None;  // ProcessingErrorData, DebugData, RenderingInfo ...
    }
    stack_.push_back(Frame{std::string(name), {}, {}, false});
}

void SysmonNormalizer::onAttribute(std::string_view name, std::string_view value) {
    if (stack_.empty()) return;
    Frame& f = stack_.back();
    if (section_ == Section::System && stack_.size() == 3) {
        if (f.name == "Provider" && name == "Name") {
            ev_->provider.assign(value);
        } else if (f.name == "Provider" && name == "EventSourceName" && ev_->provider.empty()) {
            ev_->provider.assign(value);  // classic (non-manifest) providers
        } else if (f.name == "TimeCreated" && name == "SystemTime") {
            timeSet_ = parseTimestampMs(value, ev_->timeMs);
        } else if (f.name == "Execution" && name == "ProcessID") {
            addField("ExecutionProcessID", std::string(value));
        } else if (f.name == "Execution" && name == "ThreadID") {
            addField("ExecutionThreadID", std::string(value));
        } else if (f.name == "Security" && name == "UserID") {
            addField("SecurityUserID", std::string(value));
        } else if (f.name == "Correlation" && name == "ActivityID") {
            addField("ActivityID", std::string(value));
        }
    } else if (section_ == Section::EventData && name == "Name") {
        f.dataName.assign(value);
    }
}

void SysmonNormalizer::onText(std::string_view text) {
    if (!stack_.empty()) stack_.back().text.append(text);
}

void SysmonNormalizer::onCloseElement(std::string_view /*name*/) {
    if (stack_.empty()) return;
    Frame f = std::move(stack_.back());
    stack_.pop_back();
    const size_t depth = stack_.size() + 1;  // depth of the element being closed (Event = 1)

    switch (section_) {
        case Section::System:
            if (depth == 3) {
                uint64_t n = 0;
                if (f.name == "EventID") {
                    if (parseUInt(f.text, n)) ev_->eventId = static_cast<uint32_t>(n);
                } else if (f.name == "Level") {
                    if (parseUInt(f.text, n)) ev_->level = static_cast<uint8_t>(std::min<uint64_t>(n, 255));
                } else if (f.name == "Channel") {
                    ev_->channel = std::move(f.text);
                } else if (f.name == "Computer") {
                    ev_->computer = std::move(f.text);
                } else if (f.name == "EventRecordID") {
                    if (parseUInt(f.text, n)) ev_->recordId = n;
                } else if (f.name == "Task" || f.name == "Opcode" || f.name == "Keywords") {
                    if (!f.text.empty() && f.text != "0") addField(std::move(f.name), std::move(f.text));
                }
            }
            break;
        case Section::EventData:
            if (depth == 3) {
                if (f.name == "Data") {
                    if (f.dataName.empty()) {
                        // Classic events carry positional, unnamed <Data> elements.
                        ++unnamedData_;
                        if (!f.text.empty()) addField("Data" + std::to_string(unnamedData_), std::move(f.text));
                    } else {
                        addField(std::move(f.dataName), std::move(f.text));
                    }
                } else if (!f.text.empty()) {
                    addField(std::move(f.name), std::move(f.text));  // <Binary>
                }
            }
            break;
        case Section::UserData:
            // Leaf elements below <UserData><SomeEventXml> become fields named after the element.
            if (depth >= 4 && !f.hasChild && !f.text.empty()) addField(std::move(f.name), std::move(f.text));
            break;
        case Section::None:
            break;
    }
    if (depth == 2) section_ = Section::None;
}

void SysmonNormalizer::finish(const RecordView& record) {
    if (!timeSet_) ev_->timeMs = filetimeToUnixMs(record.writtenFiletime);
    if (ev_->recordId == 0) ev_->recordId = record.recordId;
    if (ev_->provider == "Microsoft-Windows-Sysmon") normalizeSysmon();
    else if (ev_->provider == "Microsoft-Windows-Security-Auditing") normalizeSecurity();
}

void SysmonNormalizer::normalizeSysmon() {
    // Split "SHA256=...,MD5=...,IMPHASH=..." into one field per algorithm so rules and the
    // inspector can address individual hashes.
    const std::string* hashes = ev_->find("Hashes");
    if (!hashes) hashes = ev_->find("Hash");
    if (hashes && !hashes->empty()) {
        std::vector<std::pair<std::string, std::string>> extra;
        std::string_view rest = *hashes;
        while (!rest.empty()) {
            const size_t comma = rest.find(',');
            const std::string_view part = trim(rest.substr(0, comma));
            if (const size_t eq = part.find('='); eq != std::string_view::npos && eq > 0)
                extra.emplace_back(std::string(part.substr(0, eq)), std::string(part.substr(eq + 1)));
            if (comma == std::string_view::npos) break;
            rest.remove_prefix(comma + 1);
        }
        for (auto& kv : extra) {
            // Sigma uses lower-case names for digests and "Imphash" for the import hash.
            std::string key = foldCase(kv.first);
            if (key == "imphash") key = "Imphash";
            if (!ev_->find(key)) addField(std::move(key), std::move(kv.second));
        }
    }
}

void SysmonNormalizer::normalizeSecurity() {
    if (ev_->eventId != 4688 && ev_->eventId != 4689) return;
    // Security 4688 names the *creator* pid "ProcessId" and the new process "NewProcessId"
    // (both hexadecimal). Rewrite to the Sysmon vocabulary so process_creation rules and the
    // process tree treat both sources identically; the originals are preserved under new names.
    std::string newPid, creatorPid, newImage, parentImage;
    for (auto& [k, v] : ev_->fields) {
        if (k == "NewProcessId") newPid = v;
        else if (k == "ProcessId") creatorPid = v;
        else if (k == "NewProcessName") newImage = v;
        else if (k == "ParentProcessName") parentImage = v;
        else if (k == "ProcessName" && ev_->eventId == 4689) newImage = v;
    }
    auto toDecimal = [](const std::string& s) {
        uint64_t n = 0;
        return parseUInt(s, n) ? std::to_string(n) : s;
    };
    if (ev_->eventId == 4688) {
        for (auto& [k, v] : ev_->fields)
            if (k == "ProcessId") k = "CreatorProcessId";
        if (!newPid.empty()) addField("ProcessId", toDecimal(newPid));
        if (!creatorPid.empty()) addField("ParentProcessId", toDecimal(creatorPid));
        if (!newImage.empty()) addField("Image", newImage);
        if (!parentImage.empty()) addField("ParentImage", parentImage);
        if (const std::string* user = ev_->find("SubjectUserName"); user && !ev_->find("User")) {
            const std::string* domain = ev_->find("SubjectDomainName");
            addField("User", domain && !domain->empty() ? *domain + "\\" + *user : *user);
        }
    } else {
        for (auto& [k, v] : ev_->fields)
            if (k == "ProcessId") v = toDecimal(v);
        if (!newImage.empty()) addField("Image", newImage);
    }
}

}  // namespace td::evtx
