# ARP Sniffer

A C++20/Qt 6 Widgets application for macOS. The current milestones provide a working application window, lifecycle tests, and a pure Ethernet/IPv4 ARP parser. Live capture controls, sortable packet inspection, and display filters are implemented. PCAP recording, CSV export, and offline replay are implemented; release validation follows [PLAN.md](PLAN.md).

## Development environment

Install Apple's Command Line Tools (`xcode-select --install`) and Homebrew, then:

```sh
brew install cmake ninja qt libpcap pkgconf
```

Required: CMake 3.25+, Ninja, a C++20 compiler, Qt 6.5+ Widgets/Test/Concurrent, libpcap development headers/libraries, and pkg-config. Verified on macOS 27.0.1 arm64 with Apple Clang/clang-format 21.0.0, macOS SDK 27.0, CMake 4.4.3, Ninja 1.13.2, Qt 6.11.2, libpcap 1.11.0, and pkgconf 3.0.7. Linux and Windows have not been validated.

Homebrew's normal prefix is discovered automatically. If dependencies are installed elsewhere, use an ignored `CMakeUserPresets.json` preset inheriting `debug`, setting `CMAKE_PREFIX_PATH` to your Qt prefix, and setting `PKG_CONFIG_PATH` in its environment to libpcap's pkgconfig directory. Do not put personal paths in shared presets.

## Build, test, and launch

From the repository root:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
./build/debug/arp_sniffer.app/Contents/MacOS/arp_sniffer
```

Close the window to quit. `src/main.cpp` is the entry point; `src/gui/MainWindow.hpp/.cpp` owns the initial window. The executable calls libpcap's version API to validate linking without opening a capture device. It does not require administrator privileges.

Replace `debug` with `release` or `sanitizer` in all three build/test commands. The sanitizer preset enables AddressSanitizer and UndefinedBehaviorSanitizer and checks compilation/link support at configure time. Both executed successfully on the verified Apple Clang toolchain; other sanitizers are not configured. CTest runs the Qt lifecycle test using Qt's offscreen platform; it tests visibility, reopen, destruction, and event-loop shutdown without a display.

Format and check C++ files using the Command Line Tools formatter (or `clang-format` on PATH):

```sh
xcrun clang-format --dry-run --Werror src/main.cpp src/gui/MainWindow.hpp src/gui/MainWindow.cpp tests/MainWindowTests.cpp
```

Compiler warnings (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow`) provide the initial lint checks. Use `.clang-format` for four-space indentation and a 100-column limit.

## Capture and replay status

The GUI supports live interface selection, recording, and offline PCAP replay. Live capture requires explicit interface selection and appropriate capture-device permissions on an authorized network. Offline replay requires no capture privileges. Capture files are ignored; only curated synthetic fixtures in `tests/fixtures/` may be committed. See [PLAN.md](PLAN.md) for scope, network visibility limits, and acceptance criteria.

The current `.app` is a development bundle using installed Qt libraries. Standalone dependency deployment is scheduled for milestone 6.

## Packet parser

`arp::parseEthernetArp` in `src/core/ArpParser.hpp` accepts owned-by-caller frame bytes plus `PacketMetadata`. It returns `Valid` with an independent record, or `Malformed`/`Unsupported` with a reason and no record. Metadata carries the observation sequence, Unix-epoch nanosecond timestamp, interface name, captured/original lengths, and link type. Captured length must equal the input size and cannot exceed original length.

Supported frames use Ethernet link type 1 and IPv4 ARP with request/reply operations. Zero, one, or two VLAN headers using TPIDs 0x8100/0x88a8 are accepted; each raw TCI and tag order is retained. Records preserve Ethernet source/destination, sender/target MAC and IPv4 bytes, and observation metadata. Truncated headers/addresses and incorrect Ethernet/IPv4 address lengths are malformed; unsupported link types, payload types, ARP formats/operations, and complete third VLAN headers are unsupported. Ethernet padding is allowed. Probes, gratuitous ARP, and repeated packets remain separate valid observations; no pairing or address-policy assumptions are applied.

## Capture service library

`src/capture/` supplies `enumerateInterfaces()`, live/offline backend factories, and `CaptureService`. Call lifecycle methods and `takeBatch()` on the service's owning Qt thread. `start(name)` explicitly selects an interface and returns whether the start request was accepted. Initialization runs on the worker; observe queued Running/Error transitions for its outcome. Packet reads, statistics, and cleanup run on that worker. Ethernet link type is required. The BPF filter admits untagged ARP and one/two 0x8100/0x88a8 VLAN tags. Frames are copied before the next libpcap read.

`packetsAvailable`, `stateChanged`, and errors are queued onto the owning thread. Drain packets with `takeBatch()` (maximum 64 per call); the service queues at most 256 packets, each backend frame at most 65,535 bytes. Excess live observations increment `applicationDrops()`; offline replay waits for queue space instead of dropping observations. `statistics()` exposes received/kernel drops where available; unavailable counts are optional/unknown (including macOS interface drops and all offline statistics). Counters reset on restart. Stopping requests cancellation and wakes a separate pipe without joining on the owning thread; observe Stopped after worker cleanup. Destruction joins safely. Cancellation can be requested during Starting. Idle cancellation does not wait for traffic or a libpcap read timeout. Live reads drain buffered packets before waiting and are nonblocking. Queued notifications carry a session generation, so callbacks from a previous start are discarded after restart. Handles and compiled filters have RAII ownership. `ICaptureBackend` permits deterministic failure/lifecycle testing.

For authorized macOS live capture, install Wireshark's official **Install ChmodBPF.pkg** from its disk image (or About Wireshark → Folders → macOS Extras) to configure BPF device access, following [Wireshark's macOS installation guide](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallOSXInstall.html). Reopen your login session if group membership changes, then run the app as your ordinary user. Permission failures retain libpcap's error message. This project does not install privilege helpers or modify machine permissions. Select only an authorized Ethernet interface; loopback/monitor link types are rejected. Capture visibility is limited to traffic delivered to that interface; promiscuous mode does not reveal all traffic on a switched network.

Routine capture tests create synthetic PCAPs in temporary directories, requiring no live interface or privileges. Authorized live traffic validation remains milestone 6; no live network capture has been performed for milestone 3.

## Live capture window

Select an authorized interface and click Start. Starting/Stopping are asynchronous; Stop and closing the window request cancellation while controls remain responsive. The window closes after capture cleanup finishes. Status reports initialization/capture failures; elapsed time and request/reply/error, kernel/interface/application drop counters describe the session. Unknown backend statistics display as unknown. Parser failures, unsupported packets, and backend errors increment Errors. Starting a new session clears history and counters.

Click a column header to sort. Operation, IP, and MAC filters apply only to the table; IP/MAC filters match a substring of either ARP sender or target address, with MAC matching case-insensitively. Select a row to inspect its Ethernet addresses, frame lengths, and ordered VLAN TPID/TCI/VID/priority/DEI values. Timestamp display uses UTC; sorting preserves capture nanoseconds.

History retains the newest 10,000 observations in capture order, independently of sorting/filtering. Older-row removal is shown below the table and does not reduce session totals. Enter a PCAP destination before Start to record the full session; an empty destination means packets are not saved. Automated tests use deterministic records and injected capture backends; no live-network traffic is needed.

Milestone 4 stress validation (macOS 27.0.1 arm64, Apple Clang 21/Qt 6.11.2, debug build, offscreen Qt window shown): 100,000 synthetic records inserted in batches of 1,000 took 370 ms, retained 10,000 rows, and reported 90,000 evictions. The owner-thread heartbeat fired 102 times with a maximum observed gap of 13 ms. This measures deterministic playback/UI responsiveness on this machine, not live capture throughput.

## Record, export, and replay

Before live capture, enter a PCAP recording path (or leave it empty to capture without saving). The destination is opened successfully on the capture worker before activating the interface. Existing files require an explicit overwrite choice; otherwise creation is exclusive. A separate writer thread stores every delivered capture frame before display queue limits/filtering/10,000-row eviction. The writer queue holds at most 256 frames of 65,535 bytes. Overflow or write/flush failure stops capture and reports an incomplete session; it never silently discards recording data. Stop/close waits asynchronously for writer flushing and cleanup. A recording failure during closing leaves the window open with its error.

Files use classic Ethernet PCAP with nanosecond timestamps, original captured bytes, and captured/original lengths. Classic PCAP timestamp range is 1970 through February 2106; timestamps outside its representable range are rejected. Sequence numbers and interface names are application observation metadata and are not stored by classic PCAP: replay regenerates sequence numbers and labels the interface `offline`. Source timestamp precision is preserved; live microsecond sources do not gain additional timing accuracy.

Click **Open PCAP** while stopped to replay through the same capture/parse/table pipeline. Reads run on the worker and use backpressure, so a fast file does not lose observations at the display queue. The visible history remains bounded to the newest 10,000 records while session totals include all replayed observations. Non-Ethernet files, corrupt/truncated PCAP data, and invalid timestamps surface errors. Unsupported/non-ARP frames are outside the capture filter.

Choose **All retained rows** (capture order) or **Displayed rows** (current filter/sort order), then **Export CSV**. Export snapshots that scope and writes on a worker; closing waits for it. Export covers current retained decoded rows, not evicted history or all raw packets. Headers identify Unix-epoch nanoseconds, interface, ARP/Ethernet addresses, operation, VLAN TPID/TCI pairs, and frame lengths. Data fields are quoted with doubled quotes and CRLF row endings, including embedded commas/newlines. Existing CSV files require explicit overwrite confirmation; write/flush errors report incomplete output.

`SessionWriter`/`IRecordingSink` provide deterministic overflow/write/flush-failure tests. `CaptureService::setRecording` configures a session while stopped; its worker opens, queues, and finishes the writer. `setReplayMode(true)` enables offline backpressure. `MainWindow::exportRows` is a synchronous test/programmatic seam; the interactive Export button uses a worker. No authorized live-network smoke test has been performed yet (milestone 6).
