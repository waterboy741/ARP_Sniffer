# macOS Portable Release Plan

## Status and Goal

**Future work; implementation has not started.** This plan follows the release-validation work in [PLAN.md](PLAN.md#6-integrate-and-validate-the-first-release).

Produce a versioned macOS release that users can copy to a Mac and launch from Finder without installing Qt, Homebrew, CMake, or a compiler. The release must include the Qt runtime and plugins the app needs, resolve the libpcap dependency without relying on the developer's machine, and explain the separate permission setup required for live capture.

## Current State

- `CMakeLists.txt` already marks `arp_sniffer` as a macOS app bundle and assigns its bundle identifier and name.
- The README describes the existing `.app` as a development bundle that uses installed Qt libraries. Standalone deployment is still outstanding.
- The build finds libpcap through `pkg-config`, currently using the developer's installed dependency. Runtime deployment of libpcap has not been decided or validated.
- The supported development configuration is macOS arm64. A distributable Intel build or universal app has not been established.
- Live capture has a separate macOS BPF permission requirement. Bundling the app must not silently grant elevated privileges or change system permissions.

## Scope and Decisions to Make First

- Target direct download and Finder installation as a signed `.app` in a `.dmg` or `.zip`; the Mac App Store is out of scope unless separately approved and designed for its sandbox requirements.
- Choose and document the minimum supported macOS release.
- Choose release architectures. Start with separate arm64 and x86_64 builds unless the selected Qt, compiler, and libpcap dependencies all support a tested universal2 build.
- Decide how to satisfy libpcap at runtime. Prefer a supported system library where the SDK and deployment target provide it. Otherwise bundle a compatible dylib and all non-system dependencies inside the app. Do not depend on a Homebrew path or an end user's Homebrew installation.
- Decide whether this is an internal unsigned build or a public download. Public distribution should use Developer ID signing, hardened runtime as applicable, and Apple notarization; this requires the appropriate Apple developer credentials.

## Implementation Steps

### 1. Audit runtime and resource dependencies

- [ ] Build the current app in Release mode and record every non-system runtime dependency of the app executable and loaded Qt plugins.
- [ ] Inspect linked libraries with `otool -L` and verify that no path points into a developer-specific directory such as Homebrew, a Qt installation, or the build tree.
- [ ] Identify Qt libraries and plugins required by this Widgets/Concurrent app, including the macOS Cocoa platform plugin.
- [ ] Identify libpcap's origin, ABI/deployment compatibility, transitive dependencies, and redistribution license requirements. Select the system-library or bundled-library strategy above before packaging.
- [ ] Audit runtime assets, bundle metadata, icon, and any license notices required for redistributed components.

**Checkpoint:** the dependency list and libpcap strategy are written down and can be reproduced on a clean build machine.

### 2. Add reproducible release build and install configuration

- [ ] Keep the existing app bundle property, but ensure bundle-only settings are applied only on Apple builds.
- [ ] Add a Release configuration/preset and a CMake install rule that installs the `.app` bundle to a clean staging directory.
- [ ] Use Qt's CMake deployment API (`qt_generate_deploy_app_script`) or the Qt-provided `macdeployqt` tool to deploy the required Qt frameworks and plugins. Keep the deployment action tied to the Release install/package path, not ordinary debug builds.
- [ ] Add explicit deployment handling for libpcap if it is not satisfied by the supported macOS system library. Set runtime search paths so bundled libraries resolve from inside the app bundle.
- [ ] Set and verify bundle version, short version, bundle identifier, display name, icon, and minimum macOS version.
- [ ] Keep output paths and signing identities out of shared machine-specific presets; use CI secrets or local release configuration for signing.

Qt's CMake deployment API supports macOS app bundles built on macOS and is available with the project's Qt 6.5+ requirement. Validate its generated output against the actual dependencies; it does not remove the need to account for libpcap and other non-Qt libraries.

### 3. Make the capture setup installable and understandable

- [ ] Confirm the app can start, browse/replay PCAP files, and export CSV without live-capture permission.
- [ ] Document the supported BPF permission setup for live capture, including any external installer or group-membership/relogin steps that remain necessary.
- [ ] Make permission errors actionable in the GUI and README. Do not run the whole app as root, bundle a privileged helper, or alter host permissions automatically as part of packaging.
- [ ] Verify that recording and export use user-selected writable locations and that the app does not expect to write inside its read-only bundle.

### 4. Package each supported architecture

- [ ] Produce a clean Release build for every selected architecture using a compatible Qt and libpcap toolchain.
- [ ] Deploy dependencies into the staged `.app`, then inspect the bundle layout and linked-library paths.
- [ ] Produce a versioned `.dmg` or `.zip` containing the app and concise installation/capture-permission instructions.
- [ ] Include required third-party license notices and preserve upstream license terms for every bundled library.
- [ ] Record build version, source revision, architecture, minimum macOS version, and dependency versions for each artifact.

### 5. Sign and notarize distributable builds

- [ ] For public distribution, sign nested executable code, Qt frameworks/plugins, and the app using a Developer ID Application identity; enable the hardened runtime and only the entitlements the app actually needs.
- [ ] Verify the signature and Gatekeeper assessment on the final staged app/package.
- [ ] Submit the release artifact to Apple's notary service, inspect the result/log, and staple the ticket where supported.
- [ ] Repackage only after signing/notarization is complete, then verify the delivered archive or disk image still contains the signed, notarized app.
- [ ] For internal unsigned builds, mark the distribution as internal/test-only and document the expected Gatekeeper behavior instead of implying it is ready for public download.

### 6. Validate on clean Macs

- [ ] Test each architecture on a clean macOS installation or machine without Qt, Homebrew, development tools, or project dependencies installed.
- [ ] Verify Finder launch, Dock behavior, app name/icon, first launch, close/reopen, and clean application shutdown.
- [ ] Verify offline PCAP open/replay, filters, sorting, recording, and CSV export using synthetic or sanitized fixtures.
- [ ] Verify live capture with authorized traffic after separately applying the documented permission setup; also verify that denied access produces a useful error.
- [ ] Check missing interface, no traffic, unwritable export/recording destination, malformed PCAP, and app upgrade/replacement behavior.
- [ ] Inspect runtime dependencies and logs on the clean machine to ensure no developer paths or environment variables are required.
- [ ] Record the tested OS versions, architectures, actions, outcomes, and any limitations in this plan or a release validation record.

**Completion checkpoint:** the same release artifact launches and supports offline functions on a clean Mac of every advertised architecture without Qt/Homebrew installed. Live capture works after the documented permission setup, and public artifacts pass signature and notarization checks when public distribution is claimed.

### 7. Automate and document release delivery

- [ ] Add macOS CI jobs on native runners for each advertised architecture. Build, run the automated test suite, stage the app, deploy dependencies, and inspect the package.
- [ ] Keep signing and notarization credentials in protected CI secrets; do not commit certificates, passwords, or provisioning material.
- [ ] Add a release workflow that produces checksummed, versioned artifacts and preserves the validation record.
- [ ] Update `README.md` with the download/install/launch flow, supported macOS versions and architectures, dependency packaging behavior, live-capture permissions, and troubleshooting.
- [ ] Verify instructions against the exact release artifacts before publishing.

## Release Acceptance Criteria

- [ ] A clean Mac launches the delivered app from Finder with no Qt, Homebrew, compiler, or terminal setup.
- [ ] The app has no runtime linkage to build-machine or Homebrew paths; all required non-system dependencies are either bundled or explicitly identified as macOS system dependencies.
- [ ] Offline replay and CSV export work without capture privileges; live-capture permission failures are understandable and documented.
- [ ] Every advertised architecture and minimum macOS version has been tested on a clean environment.
- [ ] Public artifacts are Developer ID signed and notarized, or clearly labeled internal/test builds.
- [ ] README setup, permissions, and troubleshooting instructions match the shipped artifact.
- [ ] Release build, automated tests, package inspection, and clean-machine validation results are recorded.

## Implementation Review and Validation

When implementation begins, follow the repository's milestone review process in [PLAN.md](PLAN.md#review-and-testing-subagent-duties). Keep implementation, test, and review work scoped to the deployment milestone. Do not mark this plan complete until all release acceptance criteria have evidence recorded.

## References

- [Qt for macOS deployment](https://doc.qt.io/qt-6/macos-deployment.html) — app bundles, Qt frameworks/plugins, and `macdeployqt`.
- [Qt CMake deployment](https://doc.qt.io/qt-6/cmake-deployment.html) — deployment scripts for CMake-built Widgets applications.
- [Qt `qt_generate_deploy_app_script`](https://doc.qt.io/qt-6/qt-generate-deploy-app-script.html) — supported host/target combinations and generated install scripts.
- [Apple Developer ID signing](https://developer.apple.com/developer-id/) — signing software distributed outside the Mac App Store.
- [Apple notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) — signing, hardened runtime, submission, and notarization.
