# AGENTS.md

Working notes for AI coding agents (and new contributors) on TraceDroid. Read this before
changing anything; read `README.md` for the build and `ROADMAP.md` for what to work on.

## What this project is

An offline DFIR / SOC triage app for Android. It parses Windows Event Logs (`.evtx`),
evaluates Sigma rules, scans artifacts with YARA and draws process / network graphs.
Every input file is potentially hostile: it may come from a compromised machine and may
be crafted to attack the analyst's tooling.

## Rules that are not negotiable

1. **Offline.** Never add `INTERNET`, `ACCESS_NETWORK_STATE` or any network API, analytics,
   crash reporter or remote configuration. The `verifyOffline*` Gradle tasks fail the build
   if a dependency adds a network permission; do not weaken or bypass them.
2. **No Kotlin.** App code is Java 17. Build scripts are Groovy (`.gradle`), not `.kts`.
   Do not add the Kotlin Gradle plugin. (AndroidX pulls in `kotlin-stdlib` transitively;
   that is accepted.)
3. **Native does the heavy work.** Parsing, indexing, rule matching and graph layout live
   in C++20 under `app/src/main/cpp/`. Java must not parse evidence or loop over events.
4. **Evidence is read-only.** Imports are copies, hashed with SHA-256 and recorded in the
   case's `custody.log`. Never modify, move or delete an original; never write into an
   evidence file.
5. **License.** GPL-3.0-or-later. Every source file starts with the two-line header used
   throughout the tree. New third-party code must be GPL-compatible and vendored or
   fetched at a pinned version.
6. **Identity.** Application id and Java namespace are both `com.ccs.tracedroid`.
   Do not rename either.

## Build and test

Toolchain: JDK 17, Android SDK platform 36, NDK 28.2.13676358, CMake 3.22.1.

```bash
./gradlew assembleDebug            # both ABIs; first run clones libyara v4.5.2
./gradlew assembleRelease          # R8-minified, unsigned
```

Host build of the native core (fast; use this while iterating on C++):

```bash
cmake -S app/src/main/cpp -B build-host -DCMAKE_BUILD_TYPE=Release
cmake --build build-host -j && ./build-host/td_selftest
```

Sanitizer build (run before every native change is considered done):

```bash
cmake -S app/src/main/cpp -B build-asan -DCMAKE_BUILD_TYPE=Debug -DTD_WITH_YARA=OFF \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan -j && ./build-asan/td_selftest
```

End-to-end parser check with the synthetic fixture:

```bash
python3 app/src/main/cpp/tests/gen_synthetic_evtx.py /tmp/s.evtx
./build-asan/td_selftest /tmp/s.evtx path/to/rules.yml
```

A change is done when: both Gradle builds succeed, `td_selftest` passes in the release and
sanitizer builds, and anything user-visible was exercised on a device or emulator. Say
plainly what you did not verify.

## Map of the code

```
app/src/main/cpp/
  common/Util            UTF-16/UTF-8, case folding, time, JsonWriter, ByteWriter
  evtx/EvtxMmapReader    mmap, file/chunk headers, CRC32, record walker
  evtx/BinXmlDecoder     token stream, names, templates, substitutions, value rendering
  evtx/SysmonNormalizer  SAX events -> ParsedEvent; Sysmon and Security 4688 vocabulary
  store/EventStore       columnar index, StringPool, query(), save()/load()
  sigma/                 YamlParser, SigmaRuleCompiler, ConditionAstEvaluator, SigmaEngine
  yara/YaraEngineWrapper libyara compile + scan by fd
  graph/                 ProcessTreeBuilder, GraphLayoutEngine
  core/ForensicSession   one open case; owns everything above; locking lives here
  jni/JniBridge.cpp      the only file that includes <jni.h>
  tests/selftest.cpp     host self-test; add a check here with every native feature
app/src/main/java/com/ccs/tracedroid/
  jni/      NativeForensicEngine (the only class with native methods)
  data/     CaseRepository, ForensicCase
  model/    EventRow, GraphModel (decoders for the native binary buffers)
  ui/       cases, timeline, graph, yara
```

## Conventions that are easy to break

### Native

- **Bounds first.** Every read from mapped evidence goes through a checked accessor
  (`need()`, size checks before `loadLe`). Offsets inside BinXML are chunk-relative and
  attacker-controlled. Malformed input throws `td::ParseError`; it never crashes and never
  reads outside the chunk.
- **No recursion on input-controlled depth** without a depth limit (see `kMaxDepth`).
- **Strings are interned.** Field names and values are `uint32_t` ids in `StringPool`;
  id 0 is the empty string. Compare ids on hot paths, not text. Names the engine needs are
  in `EventStore::WellKnown` — add new ones there.
- **Case-insensitive matching** uses `foldCase` and is done once per event field
  (`EventContext`), not once per rule.
- **Cancellation and progress.** Long loops check the session's cancel flag and throw
  `td::Cancelled`. Progress callbacks run only on the thread that entered native code;
  worker threads never touch JNI.
- **Locking.** `ForensicSession::mutex_` is a shared mutex: readers (query, page, detail)
  take it shared, mutators (ingest, scan, graph build) exclusive. YARA has its own mutex.
- **Failed operations roll back** (`EventStore::truncate`, `popSource`) so a cancelled
  ingest leaves the index as it was.

### JNI contract

- The Java side holds a `long` that is a `ForensicSession*`. `NativeForensicEngine`
  guards every call with a read lock so `close()` cannot free the session mid-call.
- No C++ exception crosses the boundary: every entry point is wrapped in `guarded()`.
  Mapping: `Cancelled` -> `CancellationException`, `bad_alloc` -> `OutOfMemoryError`,
  `out_of_range` -> `IndexOutOfBoundsException`, everything else -> `NativeEngineException`.
- Evidence-derived text crosses as UTF-16 (`NewString` / `GetStringRegion`). Do not use
  `NewStringUTF` or `GetStringUTFChars` for it: modified UTF-8 cannot carry supplementary
  characters and CheckJNI aborts.
- Bulk data uses direct `ByteBuffer`s, little-endian. If you change a layout, change the
  writer (`ForensicSession::fetchPage`, `GraphLayoutEngine::serialize`) and the reader
  (`EventRow`, `GraphModel`) in the same commit. The graph buffer aliases native memory
  and must be copied before the engine lock is released.
- File descriptors passed to native code are detached; native owns and closes them.
- Adding a native method means three edits: the function in `JniBridge.cpp`, its row in
  `kMethods` with the exact signature, and the `private static native` declaration.

### Java / UI

- Never call the engine on the main thread. Heavy operations go through
  `CaseViewModel.submit` (single worker, serialised); quick reads use `TraceDroidApp.io()`.
- Screens refresh by observing `CaseViewModel.dataVersion()`. Drop stale async results
  with a serial counter, as `TimelineFragment` and `GraphFragment` do.
- User-visible text goes in `res/values/strings.xml`. Timestamps are shown in UTC.
- File access is only through the Storage Access Framework; do not request storage
  permissions.

### Persistence

- `index.tdx` is versioned by its magic (`TDXIDX02`). Change the magic whenever the layout
  changes; an unreadable snapshot is rebuilt from the EVTX copies, so no migration is needed.
- Sigma results are not persisted; they are recomputed when a case opens.

## How to add things

- **A Sigma modifier:** `SigmaRuleCompiler::compileField`, then a rule in
  `tests/selftest.cpp` that proves a match and a non-match. Unsupported features must
  throw `ParseError` with a specific message so the rule is listed as skipped, never
  silently matched or ignored.
- **A logsource mapping:** the tables in `SigmaRuleCompiler.cpp`; if the source uses
  different field names, normalise them in `SysmonNormalizer`.
- **A new evidence parser:** follow the EVTX pattern — mmap reader, bounds-checked decoder,
  normaliser into `ParsedEvent`, self-test check, fuzz target.
- **A graph node type:** `NodeType` in `ProcessTreeBuilder.hpp`, the constants in
  `GraphModel.java`, drawing in `ProcessGraphView`, detail JSON in
  `ForensicSession::graphNodeDetailJson`, rendering in `NodeInspectorSheet`.

## Testing on a device

- Check which app is in the foreground before sending any `adb shell input`; another
  process may be using the same phone. Stop if it is not TraceDroid or the system picker.
- Use only synthetic or public evidence on shared devices; real case data stays off them.
- Report the device, Android version and exactly which screens were exercised.

## Honesty about results

State what was built, what was run and what was only written. The parser has so far been
validated against a synthetic log only; do not describe it as compatible with real Windows
logs until the corpus test in `ROADMAP.md` (0.2) exists and passes. Do not publish
performance figures that were not measured.
