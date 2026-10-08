# ARP Sniffer Project Plan

## Status and Goal

Implementation authorized one milestone at a time. Use GPT-6.1 Sol for implementation, GPT-6 Luna for testing, and a separate GPT-6 Luna session for review. Give concise instructions and limit requested file access to each task’s needs. Implementation, testing, and review work concurrently and collaborate as needed. Relay findings to both implementation and testing agents; require all three signoffs before completing the milestone.

**Step 5 complete.** Steps 1–5 have unanimous implementation, testing, and review signoff. This run stops here; step 6 has not started.

### Milestone Signoff

| Step | Implementation | Testing | Review | Status |
| --- | --- | --- | --- | --- |
| 1. Build environment | Complete | Complete | Complete | Complete |
| 2. Packet parsing | Complete | Complete | Complete | Complete |
| 3. Capture service | Complete | Complete | Complete | Complete |
| 4. Live GUI | Complete | Complete | Complete | Complete |
| 5. Recording and replay | Complete | Complete | Complete | Complete |
| 6. Release validation | Pending | Pending | Pending | Not started |

Build a C++ GUI application that records and displays ARP requests and responses observed on a selected local network interface. Keep the interface responsive during capture and preserve a session on disk for later inspection.

“All traffic” means all ARP traffic delivered to the selected capture interface, subject to reported capture or application losses. Switched networks can hide other hosts’ unicast replies; network-wide visibility requires an appropriate mirror port or network tap. Promiscuous mode does not remove that limitation.

## Proposed Technical Decisions

- **Platform:** macOS first, matching the current workspace. Keep capture behind an interface so Linux support can follow; Windows/Npcap is deferred.
- **Language and build:** C++20, CMake, Ninja, and Apple Clang initially.
- **GUI:** Qt 6 Widgets with a table model and a packet-details pane.
- **Capture:** libpcap, with a worker separate from the GUI thread.
- **Tests:** Qt Test registered with CTest; synthetic packets and offline PCAP fixtures for routine tests.
- **Recording:** PCAP for captured frames; CSV export for decoded records. Preserve repeated packets as separate observations.
- **Initial packet support:** Ethernet ARP for IPv4, including single and double VLAN tags. Reject unsupported link-layer formats explicitly. IPv6 neighbor discovery and wireless monitor-mode decoding are outside the initial scope.

These are planning defaults, not installed dependencies or established repository conventions. The directory currently contains `AGENTS.md`, an empty `.gitignore`, and a Git repository without commits. CMake, Clang, Ninja, and pkg-config executables are available; versions, Qt, and libpcap development support still need verification.

## 1. Establish the Build Environment

- [x] Inventory compiler, SDK, CMake, Ninja, Qt Widgets/Test, and libpcap headers/libraries. Record compatible versions and reproducible installation instructions.
- [x] Add target-based `CMakeLists.txt` and shared debug, release, and sanitizer presets. Keep machine-specific dependency paths in ignored user presets.
- [x] Create a minimal Qt application and a meaningful test that validates the initial application lifecycle.
- [x] Configure warnings and `.clang-format`: four spaces, `PascalCase` types, `camelCase` functions/variables, and matching `.hpp`/`.cpp` filenames.
- [x] Ignore build output, local presets, and capture recordings while allowing curated fixtures. Document build and launch instructions in `README.md`.
- [x] Apply the `AGENTS.md` update described below once the actual commands and paths exist.

**Completion check:** a clean checkout configures, builds, runs tests, and opens/closes the GUI using the documented environment. Confirm sanitizer support rather than assuming every toolchain supports every sanitizer.

Planned commands, to become valid when presets are implemented:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
```

## 2. Define the Data Model and Parse Packets

- [x] Define a record containing sequence number, capture timestamp, interface, operation, Ethernet source/destination, ARP sender/target MAC and IPv4 addresses, VLAN information, and captured/original lengths.
- [x] Implement a pure parser with explicit byte-order conversion and bounds checks; avoid casting packet bytes to potentially unaligned structs.
- [x] Distinguish valid records, malformed/truncated input, and unsupported formats. Retain valid probes and gratuitous ARP observations without forcing request/reply pairing.
- [x] Add tests for requests, replies, duplicate packets, VLAN tags, short headers, invalid address lengths, unknown opcodes, and non-ARP input.

**Completion check:** expected fields match synthetic fixtures exactly; malformed input cannot cause out-of-bounds reads under supported sanitizers.

## 3. Implement the Capture Service

- [x] Enumerate interfaces and expose explicit selection. Check the selected data-link type before decoding.
- [x] Add RAII ownership for capture handles and compiled filters. Verify the capture filter admits both untagged and supported VLAN-tagged ARP while excluding unrelated traffic.
- [x] Implement start, stop, error, and restart states with an interruptible worker. Do not depend on packet arrival or the libpcap read timeout to stop an idle capture.
- [x] Copy packet data before libpcap reuses its buffer. Deliver bounded batches to the GUI through queued signals.
- [x] Report permission failures, interface removal, backend errors, and capture/application drops. Represent unavailable drop statistics as unknown.
- [x] Test lifecycle and failure paths using a fake backend and offline input.

**Completion check:** repeated start/stop and closing during an idle capture terminate cleanly, with no leaked handles or GUI-thread blocking. Document a macOS capture-permission setup that avoids routinely running the full GUI as root.

## 4. Build the Live Capture GUI

- [x] Add interface selection, Start/Stop, recording destination, capture status, elapsed time, and request/reply/error/drop counters.
- [x] Display timestamp, operation, sender/target IP and MAC, and interface in a sortable table; expose Ethernet and VLAN details in a selected-row pane.
- [x] Add display filters for operation, IP, and MAC. Filtering affects the view, not recording or total capture counters.
- [x] Bound visible history, initially to 10,000 rows, and show when older rows leave the view. Keep display filtering/retention separate from the full-session recording path to be implemented in step 5. Do not imply that step 4 saves packets.
- [x] Test control states, table insertion, sorting/filtering, selection, and empty/error states with deterministic records.

**Completion check:** fixture playback produces correct rows and counts. A 100,000-record stress run keeps the view bounded and controls responsive; record the tested machine and observed performance.

## 5. Record, Export, and Replay Sessions

- [x] Open the chosen PCAP destination successfully before live recording starts. Preserve captured frame bytes, lengths, timestamps, and link type.
- [x] Keep writer work off the GUI thread and bound its queue. Report overflow explicitly; stop recording with an actionable error on disk/write failure.
- [x] Flush and close cleanly on stop or exit. Require an explicit choice before overwriting an existing recording.
- [x] Export decoded rows to CSV with clear selection scope, headers, quoting, and timestamp format.
- [x] Open saved PCAP files through the same parser and display pipeline, without requiring capture privileges.

**Completion check:** replay of a deterministic recorded session reproduces its packets, timestamps, and decoded fields. Verify unwritable destinations, simulated write failures, malformed files, and exports without silently losing data.

## 6. Integrate and Validate the First Release

- [ ] Run automated parser, capture lifecycle, model, and recording tests with supported sanitizers. Add CI for the supported platform and ordinary unprivileged tests.
- [ ] Perform an authorized live-network smoke test against a known ARP exchange and compare fields with an independent capture tool.
- [ ] Exercise no traffic, denied access, disconnected interface, extended capture, and closing during capture/recording.
- [ ] Document setup, launch, privileges, visibility limitations, retention behavior, and troubleshooting. Verify the macOS application bundle and dependency deployment.

**Completion check:** a new contributor can follow the documented setup and record, inspect, export, and reopen an ARP session. Report any unresolved defects and untested platform behavior.

## Planned Module Layout

```text
src/core/       Packet records and pure parsing
src/capture/    libpcap adapter and capture lifecycle
src/storage/    PCAP recording/replay and CSV export
src/gui/        Widgets, table model, and presentation
tests/         Unit and integration tests
tests/fixtures/ Synthetic or sanitized packet samples
docs/          Setup, architecture, and manual test procedures
```

## Review and Testing Subagent Duties

For each milestone, assign implementation and testing to separate subagents. Run the review subagent alongside implementation and testing, collaborating as needed. Keep instructions concise, request only relevant file reads, and make edit ownership explicit. The shared workspace does not provide per-agent filesystem isolation; these are task-scope boundaries.

- A review subagent checks correctness, memory/resource ownership, threading, packet bounds, and agreement with milestone acceptance criteria.
- A testing subagent runs relevant checks, exercises failure paths, and reports reproducible failures and missing coverage. Use synthetic/offline data for routine validation; live capture remains an explicit manual check.
- The implementing agent resolves findings, reruns affected checks, and records the outcome before marking a milestone complete. Subagents must distinguish tests actually run from suggested tests.

## Planned AGENTS.md Update

At the beginning of implementation, retain the title `Repository Guidelines` and keep the guide near 200–400 words. Replace its empty-repository guidance with the agreed C++ stack, actual module paths, verified commands, formatting conventions, test expectations, and focused commit/PR requirements. Link to this plan for detailed acceptance criteria.

Include this instruction:

> During implementation, task subagents with review and testing at each milestone. Review resource ownership, packet bounds, thread safety, and acceptance criteria. Run relevant automated checks and report actual results, failures, and coverage gaps. Resolve findings and rerun affected checks before marking work complete.

## Technical References

- [Qt: Getting started with CMake](https://doc.qt.io/qt-6/cmake-get-started.html) — Qt targets and build integration.
- [libpcap official manual source](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap.3pcap.in) — capture interfaces, savefiles, permissions, visibility limits, and timeout behavior.

## Implementation Validation Record

- **Step 1:** All three agents voted complete. Debug, release, and ASan/UBSan builds and CTest passed. Native macOS window open/reopen/close and event-loop exit passed with sandbox escalation. Formatting and build-without-tests checks passed. Standalone deployment remains scheduled for step 6.
- **Step 2:** All three agents voted complete; reviewer reported no material findings. Debug, release, and ASan/UBSan CTest passed 2/2 suites. Parser coverage includes exact decoded fields, metadata, five VLAN stacks, 138 prefix truncations, 510 invalid address-length combinations, unsupported formats, probes, gratuitous/repeated observations, unaligned input, independent record ownership, 12,800 byte mutations, and 10,000 seeded random frames. No reported sanitizer diagnostics or compiler warnings. No step 3 implementation started.

- **Step 3:** GPT-6.1 Sol implementation, GPT-6 Luna testing, and the replacement GPT-6.1 Sol reviewer all voted complete. Resolved initial review findings with worker-side initialization/cleanup, asynchronous stop, buffered reads before waiting, session-gated notifications, and synchronized queue-overflow tests. Debug and ASan/UBSan passed all four CTest suites; the final reviewer independently passed all four suites over 20 repetitions. Fake-backend tests cover delayed startup/cleanup, cancellation, restart, failures, bounded delivery/drop counts, and stale events; synthetic offline tests cover filters and packet ownership. Real-device permission/interface-removal validation remains for step 6. No step 4 implementation started.

- **Step 4:** Sol implementation, Luna testing, and the new Luna reviewer worked concurrently and all voted complete. Debug and ASan/UBSan passed five CTest suites; reviewer independently passed 5/5. Tests include synthetic bytes through capture/parser/GUI, async close during startup/capture, errors, filters with invariant totals, sorting, VLAN details, and retention. A shown-window 100,000-record stress run on macOS 27.0.1 arm64 took approximately 370–373 ms, retained 10,000 and evicted 90,000 rows; measured maximum timer gap was 13 ms in testing and 18 ms in independent review. Populated-window visual inspection confirmed readable timestamps and explicit not-recording wording. Recording is disabled until step 5; no real live-network capture was exercised in this milestone. No step 5 work started.

- **Step 5:** Sol implementation, Luna testing, and Luna review all voted complete. Debug and ASan/UBSan passed six CTest suites; independent reviewer debug passed 6/6. Verified production PCAP exact bytes/lengths/nanosecond timestamps/link type, bounded writer overflow and open/write/flush errors, error visibility during stop, overwrite refusal/confirmation, CSV scopes/quoting, malformed captures, and replay backpressure. A synthetic 10,050-packet record→GUI retention/filter→CSV→replay integration test passed; recording precedes GUI queue drops and row eviction. Fixed a startup-error cancellation race and corrected the overwrite-dialog test to click actual buttons. Populated GUI inspected. No real live-network capture performed; step 6 has not started.
