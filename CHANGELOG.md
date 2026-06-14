# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-14

### Removed

- **BREAKING — JSON file output.** The `JsonReporter` class, the `-f json`
  format value, and the default `flutter_sast_report.json` artifact have been
  removed. The CLI now writes only the HTML report (and the console summary).
  Migration:
  - Drop `-f json` from any CI invocations; use `-q` to suppress console
    output or `-f console` to skip the HTML file.
  - If you imported `JsonReporter` from `package:flutter_sast/flutter_sast.dart`,
    remove the import. `ScanReport.toJson()` and `Vulnerability.toJson()` are
    still available, so consumers that want JSON can serialize the report
    themselves with `dart:convert`.

### Changed

- **CLI:** `--format` / `-f` now accepts `console` and `html` only
  (default: `console,html`).
- **CLI:** `--output` / `-o` help text now references HTML output only.
- **Docs:** README CI example replaced `-f json` with `-q`; report section
  updated to reflect the single HTML artifact.

## [0.1.1] - 2026-05-17

### Changed

- **README:** clearer limitations, example output, heuristic wording, and config notes for pub.dev.

[0.2.0]: https://github.com/umaraslam-cs/flutter_sast/releases/tag/v0.2.0

[0.1.1]: https://github.com/umaraslam-cs/flutter_sast/releases/tag/v0.1.1

## [0.1.0] - 2026-05-17

First release on pub.dev.

### Added

- **CLI** `flutter_sast` / `flutter_sast scan [dir]` — console, JSON, and HTML reports by default; `-q`, `-o`, `-f`, `--fail-on-high`, `--fail-on-any`.
- **Profiles:** `security` (default), `privacy` (iOS usage strings), `web` (CSP, `dart:io` guard, WebView allowlist).
- **Flags:** `--no-dart`, `--no-android`, `--no-ios`, `--no-pubspec`, `--no-env`, `--no-web`, `--profile`, `-r` / `--rules`, `-e` / `--exclude`.
- **`.flutter_sast.yml`** — exclude globs, rule `severity` / `exclude_globs` / `only_security_context`, Android `exported_allowlist`.
- **Inline suppressions:** `// flutter_sast:ignore RULE-ID`.
- **50+ rule IDs** — Dart (`DART-001`–`018`), Android (`AND-001`–`015`), iOS (`IOS-001`–`006`), dependencies (`DEPS-002`, `003`, `006`), build config (`CONFIG-001`, `003`, `004`), web (`WEB-001`, `002`).
- **API:** `FlutterSastScanner`, `ScanOptions`, `ScanReport`, reporters.
- **Scoring:** hygiene score with confidence weighting; `INFO` and dependency recommendations excluded from score.

### Highlights

- Heuristic Dart scanning with false-positive guards (`LineContext`, `SecretHeuristics`, comment stripping).
- Android manifest, `strings.xml`, iOS `Info.plist`, `pubspec.yaml`, `.env`, and Gradle/ProGuard config checks.
- Requires **Dart SDK 3.3+** (Flutter 3.19+).

[0.1.0]: https://github.com/umaraslam-cs/flutter_sast/releases/tag/v0.1.0
