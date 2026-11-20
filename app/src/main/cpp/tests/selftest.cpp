// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// Host-side developer self-test for the native core (not shipped in the APK).
//   td_selftest                     run the built-in unit checks
//   td_selftest file.evtx [rules]   parse a real log, optionally scan it with a Sigma rule file/dir
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <iostream>

#include "core/ForensicSession.hpp"
#include "evtx/BinXmlDecoder.hpp"
#include "sigma/SigmaEngine.hpp"
#include "sigma/YamlParser.hpp"

using namespace td;

static int failures = 0;
#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            ++failures;                                                             \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);             \
        }                                                                           \
    } while (0)

static ParsedEvent sysmonEvent(uint32_t eventId, int64_t t, std::vector<std::pair<std::string, std::string>> fields) {
    ParsedEvent e;
    e.recordId = static_cast<uint64_t>(t);
    e.timeMs = t;
    e.eventId = eventId;
    e.provider = "Microsoft-Windows-Sysmon";
    e.channel = "Microsoft-Windows-Sysmon/Operational";
    e.computer = "WS01";
    e.fields = std::move(fields);
    return e;
}

static const char* kRules = R"yaml(
title: Encoded PowerShell
id: 11111111-1111-1111-1111-111111111111
status: test
description: >
  Detects PowerShell started
  with an encoded command.
level: high
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cli:
    CommandLine|contains|all:
      - ' -enc'
      - 'bypass'
  filter:
    ParentImage|endswith: '\trusted.exe'
  condition: all of selection_* and not filter
---
title: Suspicious DNS
id: 22222222-2222-2222-2222-222222222222
level: critical
logsource:
  product: windows
  category: dns_query
detection:
  sel:
    QueryName|re: '^[a-z0-9]{12,}\.evil\.(com|net)$'
  condition: sel
---
title: Rare port or wildcard path
id: 33333333-3333-3333-3333-333333333333
level: low
logsource: {product: windows, service: sysmon}
detection:
  net:
    EventID: 3
    DestinationPort: [4444, 1337]
    DestinationIp|cidr: 10.0.0.0/8
  path:
    - Image: 'C:\Users\\*\AppData\\?emp\\*.exe'
    - CommandLine|base64offset|contains: 'http://'
  kw:
    - mimikatz
  condition: 1 of them
---
title: Linux rule is skipped
level: low
logsource: {product: linux, category: process_creation}
detection:
  sel: {Image: /bin/sh}
  condition: sel
---
title: Aggregation is skipped
level: low
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4625}
  condition: sel | count() by TargetUserName > 5
)yaml";

static void testYaml() {
    const auto docs = sigma::parseYaml("a: 1\nb:\n- x\n- 'y: z'\nc: {k: v, l: [1, 2]}\nd: |\n  line1\n  line2\ne: \"q\\tq\" # c\n");
    CHECK(docs.size() == 1);
    const auto& d = docs[0];
    CHECK(d.str("a") == "1");
    CHECK(d.get("b") && d.get("b")->items.size() == 2 && d.get("b")->items[1].scalar == "y: z");
    CHECK(d.get("c") && d.get("c")->get("l") && d.get("c")->get("l")->items.size() == 2);
    CHECK(d.str("d") == "line1\nline2\n");
    CHECK(d.str("e") == "q\tq");
}

static void testEngine() {
    EventStore store;
    const uint16_t src = store.addSource("synthetic");
    const std::string g1 = "{AAAAAAAA-0000-0000-0000-000000000001}", g2 = "{AAAAAAAA-0000-0000-0000-000000000002}",
                      g3 = "{AAAAAAAA-0000-0000-0000-000000000003}";
    store.addEvent(sysmonEvent(1, 1000, {{"ProcessGuid", g1}, {"ProcessId", "100"}, {"Image", "C:\\Windows\\explorer.exe"},
                                         {"CommandLine", "explorer.exe"}}), src, 0);
    store.addEvent(sysmonEvent(1, 2000, {{"ProcessGuid", g2}, {"ProcessId", "200"},
                                         {"Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE"},
                                         {"CommandLine", "powershell -ExecutionPolicy Bypass -enc SQBFAFgA"},
                                         {"ParentProcessGuid", g1}, {"ParentProcessId", "100"},
                                         {"ParentImage", "C:\\Windows\\explorer.exe"},
                                         {"Hashes", "MD5=AA,SHA256=BBCC,IMPHASH=DD"}}), src, 0);
    store.addEvent(sysmonEvent(22, 2500, {{"ProcessGuid", g2}, {"ProcessId", "200"}, {"QueryName", "abcdef0123456789.evil.com"},
                                          {"QueryResults", "10.1.2.3"}}), src, 0);
    store.addEvent(sysmonEvent(3, 2600, {{"ProcessGuid", g2}, {"ProcessId", "200"}, {"DestinationIp", "10.1.2.3"},
                                         {"DestinationPort", "4444"}}), src, 0);
    store.addEvent(sysmonEvent(3, 2700, {{"ProcessGuid", g2}, {"ProcessId", "200"}, {"DestinationIp", "10.1.2.3"},
                                         {"DestinationPort", "4444"}}), src, 0);
    store.addEvent(sysmonEvent(1, 3000, {{"ProcessGuid", g3}, {"ProcessId", "300"},
                                         {"Image", "C:\\Users\\bob\\AppData\\Temp\\x.exe"}, {"CommandLine", "x.exe"},
                                         {"ParentProcessGuid", g2}, {"ParentProcessId", "200"}}), src, 0);
    store.addEvent(sysmonEvent(1, 3500, {{"ProcessId", "400"}, {"Image", "C:\\Windows\\System32\\cmd.exe"},
                                         {"CommandLine", "cmd /c echo aHR0cDovL2V2aWw="}, {"ParentProcessId", "300"}}), src, 0);
    store.finalize();

    sigma::SigmaEngine engine;
    const size_t loaded = engine.loadRules(kRules, "selftest.yml");
    CHECK(loaded == 3);
    CHECK(engine.diagnostics().size() == 2);
    for (const auto& d : engine.diagnostics()) std::printf("  skipped: %s -> %s\n", d.title.c_str(), d.message.c_str());

    std::atomic<bool> cancel{false};
    engine.scan(store, nullptr, cancel);
    const auto& counts = engine.ruleHitCounts();
    CHECK(counts[0] == 1);  // encoded powershell
    CHECK(counts[1] == 1);  // dns regex
    CHECK(counts[2] == 4);  // 2 network + wildcard path + base64offset
    CHECK(store.severity(1) == 4);
    CHECK(store.severity(2) == 5);
    CHECK(store.severity(0) == 0);
    CHECK(engine.hitsForEvent(1).size() == 1);
    if (!engine.hitsForEvent(1).empty()) CHECK(engine.hitKeys(engine.hitsForEvent(1)[0]).size() == 2);

    QuerySpec q;
    q.text = "POWERSHELL";
    CHECK(store.query(q).size() == 1);
    q.text = "evil\\.(com|org)$";
    q.regex = true;
    CHECK(store.query(q).size() == 1);
    q = {};
    q.minSeverity = 4;
    CHECK(store.query(q).size() == 2);

    graph::BuildOptions opts;
    auto g = graph::ProcessTreeBuilder().build(store, opts);
    CHECK(g.nodes.size() == 6);  // 4 processes + 1 aggregated connection + 1 dns
    graph::GraphLayoutEngine layout;
    CHECK(layout.layout(g, graph::LayoutMode::Hierarchical) == graph::LayoutMode::Hierarchical);
    size_t roots = 0, net = 0;
    for (const auto& n : g.nodes) {
        if (n.parent < 0) ++roots;
        if (n.type == graph::NodeType::Network) {
            ++net;
            CHECK(n.count == 2);
        }
    }
    CHECK(roots == 1);
    CHECK(net == 1);
    CHECK(layout.layout(g, graph::LayoutMode::ForceDirected) == graph::LayoutMode::ForceDirected);
    const auto bytes = graph::GraphLayoutEngine::serialize(g, graph::LayoutMode::ForceDirected);
    CHECK(bytes.size() > 32 + g.nodes.size() * 16);

    const std::string path = std::string(std::getenv("TMPDIR") ? std::getenv("TMPDIR") : "/tmp") + "/td_selftest.idx";
    store.save(path);
    EventStore copy;
    CHECK(copy.load(path));
    CHECK(copy.size() == store.size());
    CHECK(copy.field(1, copy.wk().CommandLine) == store.field(1, store.wk().CommandLine));
    std::remove(path.c_str());
}

static void testYara() {
    if (!yara::YaraEngineWrapper::available()) {
        std::printf("  (built without libyara; YARA checks skipped)\n");
        return;
    }
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "td_selftest_yara";
    fs::create_directories(dir);
    {
        std::ofstream(dir / "demo.yar") << "rule Demo : dropper test {\n  meta:\n    author = \"selftest\"\n    score = 80\n"
                                           "  strings:\n    $a = \"EVILMARK\"\n    $b = { 4D 5A 90 00 }\n  condition:\n    $a and $b\n}\n";
        std::ofstream(dir / "broken.yar") << "rule Broken { condition: undefined_identifier }\n";
        std::ofstream artifact(dir / "sample.bin", std::ios::binary);
        artifact << "MZ" << '\x90' << '\0' << std::string(1000, 'A') << "EVILMARK" << std::string(50, 'B');
    }
    ForensicSession session;
    CHECK(session.compileYaraRules(dir.string()) == 1);
    const std::string diag = session.yaraDiagnosticsJson();
    CHECK(diag.find("broken.yar") != std::string::npos);
    const int fd = ::open((dir / "sample.bin").c_str(), O_RDONLY);
    CHECK(fd >= 0);
    const std::string result = session.yaraScanFd(fd, "sample.bin", 30);
    ::close(fd);
    CHECK(result.find("\"rule\":\"Demo\"") != std::string::npos);
    CHECK(result.find("\"dropper\"") != std::string::npos);
    CHECK(result.find("\"offset\":1004") != std::string::npos);  // $a
    CHECK(result.find("\"name\":\"score\",\"value\":\"80\"") != std::string::npos);
    std::printf("  yara: %s\n", result.substr(0, 260).c_str());
    fs::remove_all(dir);
}

int main(int argc, char** argv) {
    if (argc >= 2) {
        try {
            ForensicSession session;
            std::cout << session.ingestEvtx(argv[1], nullptr) << "\n";
            if (argc >= 3) {
                std::cout << "rules loaded: " << session.loadSigmaRules(argv[2]) << "\n";
                std::cout << session.runSigmaScan(nullptr).substr(0, 4000) << "\n";
            }
            std::cout << session.statsJson() << "\n";
            QuerySpec all;
            const uint32_t n = session.query(all);
            for (uint32_t i = 0; i < n && i < 3; ++i) std::cout << session.eventDetailJson(i) << "\n";
            graph::BuildOptions opts;
            const auto geometry = session.buildGraph(graph::LayoutMode::Hierarchical, opts, nullptr);
            std::cout << "graph bytes: " << geometry.size() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
            return 2;
        }
        return 0;
    }
    testYaml();
    testEngine();
    testYara();
    std::printf(failures ? "%d check(s) failed\n" : "all checks passed\n", failures);
    return failures ? 1 : 0;
}
