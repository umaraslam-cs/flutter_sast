# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **False-positive guards** for route constants (`editPassword = '/edit-password'`),
  safe local log paths (`tempDir.path` + `K.logFilename`), and FlutterFire OAuth
  client IDs in `firebase_options.dart`.
- **Line context layer** (`LineContext`) to cut false positives: test/mock lines,
  UI strings, benign prefs keys, dev/staging HTTP hosts, and safer logging rules.
- **`FindingConfidence`** on every finding (`LOW` / `MEDIUM` / `HIGH`) in console,
  JSON, and HTML reports.
- **30 rule IDs** including `AND-008` (Google Maps API key in manifest),
  `AND-009` (invalid `uses-permission`), AppsFlyer / RevenueCat key patterns.
- **`projectName`** from `pubspec.yaml`; absolute `projectPath` in reports.
- Root CLI shorthand: `flutter_sast` and `flutter_sast .` (no `scan` required).
- Default outputs: console + `flutter_sast_report.json` + `.html`; clickable
  `file://` link for HTML.
- `-q` / `--quiet`, smarter `-o` paths, and `test/fixtures/` for analyzer tests.

### Changed

- **DART-001 Hardcoded Password**: word-boundary before `password` so identifiers
  like `editPassword` are not matched; route path string values are ignored.
- **DART-001 Google OAuth Client ID**: skipped in `firebase_options.dart`; downgraded
  to INFO when reported elsewhere.
- **DART-005b**: skips OS temp/cache dir + app constant path joins; adds confidence.
- **DEPS-001**: no longer lists `http` when cleartext is already covered by network rules.
- **Hygiene score** uses capped deductions (no more automatic 0/100 on noisy apps).
- **`riskLevel` `ADVISORY`** when only `DEPS-*` findings and nothing HIGH+.
- **Firebase client keys**: `INFO` severity, low confidence, client-key guidance.
- **DEPS-002 / DEPS-003** skipped for pure Dart / CLI packages (no `flutter` SDK dep).
- Reduced false positives: `FFUploadedFile` path traversal, session prefs, static
  logs, `api.example.com`, duplicate secret patterns per line.

### Fixed

- Self-scan no longer flags rule implementation files under `lib/src/rules/dart/`.

## [0.1.0] - 2026-05-13

### Added

- Initial public release of `flutter_sast`, a SAST and vulnerability
  assessment CLI for Flutter / Dart projects.
- Command-line entry point `flutter_sast` using the **`scan`** subcommand:
  `flutter_sast scan [directory]` (directory defaults to `.`; example:
  `flutter_sast scan /path/to/app`). Scan options include output,
  format (console / JSON / HTML), exclude paths, rule filters, and
  CI-friendly exit codes (`--fail-on-high`, `--fail-on-any`).
- **`flutter_sast -v`** and **`flutter_sast --version`** (single argument only)
  print the tool version without a subcommand.
- Programmatic API: `FlutterSastScanner`, `ScanOptions`, `ScanReport`,
  `Vulnerability`, `Severity`, and three reporters (`ConsoleReporter`,
  `JsonReporter`, `HtmlReporter`).
- Initial rule set covering 27 distinct rule IDs (see [Unreleased] for updates to 30):

  Dart source rules:
    - `DART-001` — Hardcoded secrets (API keys, AWS keys, Firebase keys,
      Google OAuth, private key blocks, hardcoded passwords, bearer
      tokens, Stripe, Twilio, SendGrid, Slack, GitHub tokens).
    - `DART-002` — Insecure HTTP URL (cleartext traffic).
    - `DART-002b` — `badCertificateCallback` returning `true`.
    - `DART-002c` — Custom `HttpClient.findProxy` with hardcoded PROXY.
    - `DART-002d` — Dio `onBadCertificate` returning `true`.
    - `DART-003` — `SharedPreferences` storing sensitive keys in plaintext.
    - `DART-003b` — `GetStorage` storing sensitive keys in plaintext.
    - `DART-003d` — Logging sensitive values via `print` / `debugPrint` / `log`.
    - `DART-004` — Use of MD5.
    - `DART-004b` — Use of SHA-1.
    - `DART-004c` — Use of insecure `Random()` for security material.
    - `DART-004d` — AES in ECB mode.
    - `DART-004e` — Hardcoded IV / salt / nonce literal.
    - `DART-005` — SQL injection via string interpolation.
    - `DART-005b` — Path traversal via unjoined user input.
    - `DART-005c` — Use of `dart:mirrors`.
    - `DART-005d` — Unrestricted JavaScript mode in WebView.
    - `DART-005e` — Sensitive data placed on system clipboard.
    - `DART-005f` — Biometric authentication with `useErrorDialogs: false`.

  Android manifest analyzer rules:
    - `AND-001` — `android:debuggable="true"`.
    - `AND-002` — `android:allowBackup="true"`.
    - `AND-003` — `android:usesCleartextTraffic="true"`.
    - `AND-004` — Exported component without `android:permission`.
    - `AND-005` — External storage permissions.
    - `AND-006` — `RECEIVE_BOOT_COMPLETED` permission.
    - `AND-007` — Missing `android:networkSecurityConfig`.

  iOS Info.plist analyzer rules:
    - `IOS-001` — `NSAllowsArbitraryLoads` enabled.
    - `IOS-002` — `NSExceptionAllowsInsecureHTTPLoads` enabled.
    - `IOS-003` — `NSAllowsArbitraryLoadsInWebContent` present.
    - `IOS-004` — `UIFileSharingEnabled` enabled.
    - `IOS-005` — `LSSupportsOpeningDocumentsInPlace` enabled.
    - `IOS-006` — Sensitive usage description keys disclosed.

  Pubspec analyzer rules:
    - `DEPS-001` — Risky dependencies declared.
    - `DEPS-002` — Recommended security packages missing.
    - `DEPS-003` — No certificate-pinning package detected (advisory).

[0.1.0]: https://github.com/umaraslam-cs/flutter_sast/releases/tag/v0.1.0
