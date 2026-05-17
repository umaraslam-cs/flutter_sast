# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Noise reduction:** removed `DEPS-001` (risky package declarations), `DEPS-004`
  (unused security deps), `AND-006`, `AND-009`, and `DART-005c` (`dart:mirrors`).
- **`DART-004` / `DART-004b`:** only flag MD5/SHA-1 in security-sensitive context;
  SHA-1 skips thumbprint/display use.
- **`AND-007`:** only when cleartext traffic is allowed or `targetSdkVersion` &lt; 28.
- **`IOS-006`:** flags empty or generic usage-description strings (privacy profile),
  not mere presence of a permission key.
- **`DART-009`:** INFO, excluded from score; **`DART-002c`:** INFO, skipped when
  behind a debug guard.
- **`DEPS-003`:** INFO advisory; improved in-code pinning detection
  (`SecurityContext`, `pinnedCertificates`).

## [0.2.0] - 2026-05-17

### Added

- **`.flutter_sast.yml`** project config: exclude globs, rule overrides, Android exported
  allowlist, scan profiles (`security`, `privacy`, `web`).
- **Inline suppressions:** `// flutter_sast:ignore RULE-ID reason`.
- **New rules:** `DART-006` (high-precision credentials), `DART-007` (env encryption keys),
  `DART-008`/`DART-009` (header/token logging), `DART-010` (WebView allowlist),
  `DART-002e` (Remote Config–gated TLS pinning), `DART-011` (HTTP inspector),
  `AND-010` (MANAGE_EXTERNAL_STORAGE), `AND-011` (SDK client token in strings.xml),
  `CONFIG-001` (env files not gitignored), `DEPS-004` (unused security deps),
  `IOS-003b` (dev ATS domain template), `WEB-001`/`WEB-002` (web profile).
- **`SecretHeuristics`** and regression tests (`test/regression_fixtures_test.dart`, T01–T08).

### Changed

- **Scoring:** `100 − Σ(severityWeight × confidenceMultiplier)`; `Recommendation` and
  `INFO` findings excluded from score (`scored: false` on DEPS advisories).
- **DART-001:** skips `*.g.dart`, locale i18n constants, storage key names, low-entropy
  password literals; Bearer requires JWT/`Bearer ` prefix.
- **DART-002b:** downgrades to **MEDIUM** when `validateCertificate` + fingerprint nearby.
- **DART-004:** suppresses MD5 used only for cache keys.
- **DART-005b:** skips `toString()` display strings and `File(` inside string literals.
- **AND-004:** only `activity`/`service`/`receiver`/`provider`; SDK allowlist; never `<application>`.
- **IOS-006:** omitted from default `security` profile (use `privacy` profile).
- **DEPS-002/003:** `Recommendation` category; DEPS-003 skipped when in-code pinning detected.

### Added (continued from pre-release)

- **False-positive guards** for route constants (`editPassword = '/edit-password'`),
  safe local log paths (`tempDir.path` + `K.logFilename`), and FlutterFire OAuth
  client IDs in `firebase_options.dart`.
- **Line context layer** (`LineContext`) to cut false positives: test/mock lines,
  UI strings, benign prefs keys, dev/staging HTTP hosts, and safer logging rules.
- **`FindingConfidence`** on every finding (`LOW` / `MEDIUM` / `HIGH`) in console,
  JSON, and HTML reports.
- **30 rule IDs** including `AND-008` (maps platform API key in manifest),
  `AND-009` (invalid `uses-permission`), third-party SDK key patterns.
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
- Reduced false positives: upload model `toString` path traversal, session prefs, static
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
