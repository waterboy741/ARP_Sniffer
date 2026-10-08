# First release validation

## Scope and evidence

The supported development environment is macOS arm64 with installed Qt/libpcap dependencies. Linux, Windows, Intel macOS, standalone deployment, signing, notarization, and launch on a clean Mac without dependencies have not been validated. The GitHub Actions workflow in `.github/workflows/macos.yml` runs ordinary unprivileged debug/release/ASan+UBSan tests on `macos-15` arm64. Its [corrected hosted run](https://github.com/waterboy741/ARP_Sniffer/actions/runs/37780116631) passed all three jobs on October 8, 2026.

The first hosted configure attempt exposed Homebrew's keg-only libpcap discovery: its `.pc` file was outside pkg-config's default search path. CI now persists the formula-derived `lib/pkgconfig` directory in `PKG_CONFIG_PATH` before configuration and verifies discovery in a separate step. A local fresh configure with default pkg-config search disabled reproduced the missing-package failure and succeeded with this explicit directory. The corrected hosted run passed libpcap discovery, configuration, build, tests, and bundle checks in debug, release, and sanitizer jobs.

The fresh Release bundle audit found a valid `Contents/Info.plist`, bundle identifier `edu.cpre5300.arp-sniffer`, name `ARP Sniffer`, version `0.1.0`, and executable `Contents/MacOS/arp_sniffer`. `otool -L` reports installed Homebrew QtWidgets, QtGui, QtConcurrent, QtCore and libpcap paths plus macOS system frameworks/libraries. The Cocoa platform plugin is installed with Qt and is not copied into the bundle. This is a development application bundle, not a portable release artifact. Follow [../MACOS_PORTABILITY_PLAN.md](../MACOS_PORTABILITY_PLAN.md) for future deployment work.

Reproduce the audit after building Release:

```sh
plutil -lint build/release/arp_sniffer.app/Contents/Info.plist
otool -L build/release/arp_sniffer.app/Contents/MacOS/arp_sniffer
"$(brew --prefix qt)/bin/qtpaths" --query QT_INSTALL_PLUGINS
open build/release/arp_sniffer.app
```

Verify native launch, readable controls, close/reopen, and clean exit. An offscreen test passing does not establish Finder/Cocoa behavior. Audit dependency paths again after upgrading Qt/libpcap.

## Contributor workflow

Follow the README installation/build commands, then launch as an ordinary user. For offline use, choose **Open PCAP**, inspect a row and its details, sort/filter, select **All retained rows** or **Displayed rows**, and export CSV to a writable user directory. For live recording, configure BPF access using the official Wireshark ChmodBPF installer, select an authorized Ethernet interface, choose a new PCAP destination, and press **Start**. Stop before opening the recorded file. Confirm request/reply counts, timestamps, address fields, details, CSV scope, and replay totals.

Display history keeps the newest 10,000 observations. Display filters and eviction do not change recording or session totals. CSV exports current retained decoded rows; PCAP preserves raw captured frames. Capture/application drops and writer errors describe separate losses. A writer overflow/write/flush error stops capture and marks the recording incomplete. Unknown backend drop statistics are not zero.

Native validation on the development Mac exposed a disabled Save button in the macOS CSV save panel despite a valid filename and writable directory. CSV export now uses Qt's widget save dialog with a default `.csv` suffix and the application's explicit overwrite confirmation. The native PCAP open dialog remains available.

## Recorded step-six results

On the documented macOS arm64 development environment, an authorized `en0` recording ran for 312.8 seconds and retained all 33 observations: 17 requests and 16 replies. Parser errors, kernel drops, and application drops were zero; interface drop statistics were unknown. An overlapping independent `tcpdump` capture contained 26 packets. All 26 matched app-recorded bytes and captured/original lengths exactly, with timestamp differences at most 3 microseconds. Gateway ARP request/reply fields aligned between captures. Different capture windows account for the comparison scope; no claim is made that the independent capture covered all 33 observations.

GUI replay restored 33 rows, and the corrected CSV picker exported 33 rows labeled `offline`. Automated picker regressions passed in debug and ASan/UBSan: extensionless filenames receive `.csv`, cancellation creates no export, overwrite refusal preserves existing content, and confirmation replaces it. Raw captures were removed after comparison and never entered the repository. Physical interface disconnection was not exercised because the active chat depended on that network connection; the user explicitly accepted this documented validation gap for step six. The 312.8-second run provides the recorded duration evidence, not a longer soak-test claim.

## Authorized live smoke procedure

Run only on an interface/network you are authorized to observe. Obtain BPF access before proceeding; do not run the full GUI as root. Use a writable temporary directory and keep traffic captures out of Git.

1. Select the same Ethernet interface in ARP Sniffer and Wireshark. Use an independent capture filter that includes the expected ARP traffic (for an untagged exchange, `arp`). Start both captures before generating traffic.
2. Identify a known local IPv4 peer and record its expected IPv4/MAC mapping. Trigger one ordinary local exchange, for example `ping -c 1 PEER_IPV4`. An existing ARP cache entry may prevent new ARP; wait for normal cache expiry or use a controlled peer. Do not flush shared network state merely to force a packet.
3. Find the same request/reply observations in both captures. Compare operation, sender/target IPv4 and MAC, Ethernet source/destination, VLAN tags if present, captured/original lengths, and timestamp precision. Do not require packet pairing or identical counts when the independent tools start/stop at different times.
4. Stop ARP Sniffer, export retained/displayed CSV, reopen its PCAP, and compare decoded fields and timestamps. Classic PCAP does not save application sequence numbers/interface names; replay uses `offline`.
5. Record OS/architecture, dependencies, interface/link type, duration, independent tool/version, observed packets, comparison results, and all drops/errors. Record only sanitized summaries in this repository.

## Failure and duration checks

| Check | Expected observation | Evidence required |
| --- | --- | --- |
| Idle/no ARP traffic | Controls remain responsive; Stop and close finish without waiting for packets | Actual native duration and shutdown result; fake-backend tests are separate evidence |
| Denied BPF access | Status retains the libpcap permission error; replay/export remain available | Ordinary-user interface/error result |
| Disconnect selected interface | A reported backend error or an explicit observed idle result; application stays responsive and can stop/restart | Actual unplug/reconnect behavior; do not assume every interface backend detects disconnection |
| Extended capture with recording | Responsive controls, bounded rows, explicit losses/errors, flushed PCAP on Stop | Duration, packet totals, retained/evicted rows, drops, recording/replay comparison |
| Close during capture/recording | Asynchronous stop and writer flush complete; recording failures keep error visible | Native close result and reopened PCAP |
| Unwritable destination/malformed PCAP | Actionable error without silently claiming successful output | Actual failure path or deterministic injected-test result |

An absent live-network result remains an acceptance gap, even when deterministic fake/offline tests pass. See [../PLAN.md](../PLAN.md) for milestone status and the final validation record.
