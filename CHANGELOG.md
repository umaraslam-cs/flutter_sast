# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Initial rule set covering 28 distinct rule IDs:

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
    - `DART-003c` — `Hive` storing sensitive keys without encryption.
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
    - `DEPS-003` — Build does not appear to use code obfuscation.

[0.1.0]: https://github.com/umaraslam-cs/flutter_sast/releases/tag/v0.1.0
