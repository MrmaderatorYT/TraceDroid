# TraceDroid

Offline digital forensics & incident response (DFIR) and SOC triage for Android, by CyberCraft Studio.

TraceDroid parses Windows Event Logs (`.evtx`, including Sysmon), evaluates Sigma rules, scans
artifacts with YARA and reconstructs process / network graphs — entirely on the device.
There is no network permission, no telemetry and no cloud dependency; the build fails if any
dependency tries to add a network permission (`verifyOffline*` Gradle tasks).

* Application id: `com.ccs.tracedroid` · Java namespace: `com.ccs.tracedroid`
* UI: Java 17, Material 3 (no Kotlin sources, no Kotlin Gradle plugin)
* Core: C++20 via the NDK (`arm64-v8a`, `x86_64`)
* License: GNU GPL v3.0 or later (see `LICENSE`); bundles libyara (BSD-3-Clause)

## Build

Requirements: JDK 17, Android SDK platform 36, NDK 28.2.13676358, CMake 3.22.1, git.

```bash
./gradlew assembleDebug
```

The first native configure clones libyara v4.5.2 into `app/src/main/cpp/third_party/yara`
(or run `scripts/fetch_third_party.sh` beforehand for a fully offline build afterwards).

### Host self-test of the native core

```bash
cmake -S app/src/main/cpp -B build-host -DCMAKE_BUILD_TYPE=Release && cmake --build build-host -j
./build-host/td_selftest                      # unit checks (YAML, Sigma, store, graph, YARA)
./build-host/td_selftest log.evtx rules/      # parse a real log and scan it with Sigma rules
```

## Layout

```
app/src/main/cpp/
  common/   Util                 UTF-16/UTF-8, case folding, time, JSON + binary writers
  evtx/     EvtxMmapReader       mmap'd ElfFile / ElfChnk / record walker with CRC validation
            BinXmlDecoder        BinXML tokens, chunk string table, templates, substitutions
            SysmonNormalizer     System/EventData/UserData -> flat fields, Sysmon + 4688 vocabulary
  store/    EventStore           columnar index with interned strings, queries, snapshot file
  sigma/    YamlParser           dependency-free YAML subset
            SigmaRuleCompiler    logsource mapping, modifiers, condition parser
            ConditionAstEvaluator, SigmaEngine (multi-threaded batch scan)
  yara/     YaraEngineWrapper    libyara compile + scan by file descriptor
  graph/    ProcessTreeBuilder, GraphLayoutEngine (tidy tree + force-directed)
  core/     ForensicSession      one case; the object behind the JNI handle
  jni/      JniBridge.cpp
app/src/main/java/com/ccs/tracedroid/
  jni/      NativeForensicEngine, NativeProgressListener, NativeEngineException
  data/     CaseRepository (case storage, SAF import, SHA-256, custody log)
  ui/cases  case list, workspace, overview      ui/timeline  paged event list + detail sheet
  ui/graph  ProcessGraphView + inspector        ui/yara      rule compiler + artifact scanner
```

## Supported Sigma features

`title`, `id`, `level`, `tags`, `logsource` (Windows categories and services mapped to
channels / event ids), selections as maps, lists of maps and keyword lists, modifiers
`contains`, `startswith`, `endswith`, `all`, `re` (+`i`, `m`), `base64`, `base64offset`,
`wide`/`utf16le`/`utf16be`/`utf16`, `windash`, `cidr` (IPv4), `exists`, `lt/lte/gt/gte`,
`cased`, wildcards `*` `?`, and conditions with `and`, `or`, `not`, parentheses,
`1 of` / `N of` / `all of` with patterns and `them`.

Not supported (such rules are skipped and listed under "rules skipped"): aggregations
(`| count() ...`), correlation rules, `action: global` collections, `fieldref`, `expand`,
and regular expressions outside the ECMAScript dialect of `std::regex` (e.g. look-behind).
