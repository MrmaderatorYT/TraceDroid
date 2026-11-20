# TraceDroid roadmap

Where the project stands and what comes next. Items are ordered by priority inside each
milestone; a milestone is done when every "exit check" under it passes.

## Current state (0.1.0)

Working and verified:

- Debug and R8-minified release builds for `arm64-v8a` and `x86_64`.
- Native core self-test (`td_selftest`) passes under AddressSanitizer / UBSan.
- On-device smoke test on a Pixel 7a (Android 17): case creation, EVTX import, Sigma scan,
  timeline, event detail, graph (tree and force), node inspector, YARA compile and scan,
  reload from the saved index.

Known gaps:

- The EVTX / BinXML parser has only been run against a synthetic log produced by
  `tests/gen_synthetic_evtx.py`. It has not been checked against logs written by Windows.
- No measurements of speed or memory on large dumps. EVTX ingest is single-threaded.
- No automated tests on the Java side and no CI.
- Folder import, regex and severity filters, cancel, and graph gestures were not exercised
  in the smoke test.

## 0.2 — Parser correctness on real evidence

The parser is the foundation; nothing else is trustworthy until this is done.

1. Build a corpus of real `.evtx` files (Security, System, Sysmon, PowerShell, Defender,
   dirty and truncated logs) kept outside the repository, with a manifest of SHA-256 hashes.
2. Differential test: compare TraceDroid's decoded fields per record against a reference
   decoder (`python-evtx` or `evtx_dump`) and fail on any mismatch.
3. Fix what the corpus finds. Expected problem areas: templates referenced across records
   in unusual order, array-typed substitutions, `UserData` shapes, classic (non-manifest)
   providers, records spanning damaged chunks.
4. Record carving for dirty logs: resynchronise on the next record signature instead of
   abandoning the rest of a chunk.
5. Fuzz `BinXmlDecoder`, `EvtxMmapReader`, `YamlParser` and `EventStore::load` with
   libFuzzer on the host; keep the crash corpus as regression inputs.

Exit checks: zero field mismatches on the corpus; 24 CPU-hours of fuzzing with no crash;
damaged-chunk logs yield every record the reference decoder yields.

## 0.3 — Scale

1. Benchmark harness on host and device: ingest MB/s, peak RSS, index size, query latency,
   Sigma scan events/s. Publish the numbers in the README; set budgets from them.
2. Parallel EVTX ingest: decode chunks on worker threads, intern into the store in order.
3. Memory: release mapped pages more aggressively, cap per-value length in the index with
   the full value still available from the raw record.
4. Replace `std::regex` (slow, ECMAScript only) with a bundled linear-time engine such as
   RE2, for both timeline search and Sigma `|re`.
5. Graph: level-of-detail clustering for trees above the 20 000-node cap instead of
   truncation; incremental rebuild when only severities changed.

Exit checks: a 500 MB Sysmon log ingests on a mid-range phone without the app being killed;
keyword query under one second on the resulting index; numbers recorded in the README.

## 0.4 — Detection coverage

1. Run the full public SigmaHQ Windows rule set; track the share of rules that compile and
   list every reason for a skip.
2. Add what the skip list justifies, most common first: `fieldref`, `expand` placeholders,
   `action: global` collections, then aggregation / correlation rules
   (`event_count`, `value_count`, `temporal`).
3. Field-mapping tables for more sources so generic rules apply (Security 4624/4625/4648,
   4698 scheduled tasks, 7045 services, PowerShell 4103/4104, Defender 1116/1117).
4. YARA: enable the `hash` module (bundle a small digest implementation rather than
   OpenSSL), scan process memory dumps by region, show all matches with paging.
5. Rule-pack management: enable / disable individual rules and packs, show pack version
   and hash in the custody log.

Exit checks: at least 90% of SigmaHQ Windows rules compile; every skipped rule has a
specific reason shown in the app.

## 0.5 — Analyst workflow

1. Timeline: time-range picker, field-scoped search (`Image:powershell`), saved filters,
   jump from an event to its node in the graph and back.
2. Bookmarks and analyst notes on events and nodes, stored per case.
3. Reporting: export a case report (findings, bookmarked events, hashes, custody log) to
   PDF and JSON through the Storage Access Framework. Export is user-initiated only.
4. Case export / import as a single archive with integrity hashes.
5. Graph: search and highlight, collapse subtrees, time slider to replay process activity.
6. Localisation: Ukrainian first, then others; all strings already live in `strings.xml`.

## 0.6 — More evidence types

Each new parser follows the EVTX pattern: mmap reader, normaliser into the shared field
vocabulary, fuzz target, corpus test.

1. Windows: Prefetch, Amcache / Shimcache, scheduled-task XML, `$MFT` and USN journal.
2. Linux: auditd, journald export, auth logs (unlocks non-Windows Sigma rules).
3. Network: PCAP summary (flows, DNS, TLS SNI) joined to process activity by time and address.
4. IOC lists (hashes, IPs, domains) matched against the index.

## 1.0 — Release readiness

1. CI: build both ABIs, run `td_selftest` under sanitizers, corpus differential test,
   Java unit tests, lint, the `verifyOffline` check.
2. Reproducible builds and signed releases; F-Droid metadata.
3. Security review of the native attack surface (every parser consumes hostile input).
4. Accessibility pass (TalkBack on the graph, contrast, font scaling) and tablet layouts.
5. User documentation and a sample case built from public, redistributable evidence.

## Standing constraints

These do not change with any milestone:

- No network permission, no telemetry, no cloud dependency.
- Java 17 for the app, C++20 for the core, no Kotlin sources.
- Heavy work stays native; the Java layer displays and orchestrates.
- Evidence is copied, hashed and never modified; every import is logged.
- GPL-3.0-or-later; bundled third-party code must be GPL-compatible.
