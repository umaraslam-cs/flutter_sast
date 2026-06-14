# flutter_sast

[![Dart SDK](https://img.shields.io/badge/sdk-%3E%3D3.3.0-brightgreen)](https://dart.dev/get-dart)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight static security scanner for **Flutter** and **Dart** projects. One command checks your app code, platform files, and dependencies for common security misconfigurations, then prints a summary and writes an HTML report.

> ⚠️ Uses regex and line-based **heuristics** — not full AST analysis, dataflow, or a penetration test. Treat findings as a triage list and review each in context. ([Limitations](#limitations))

Requires **Dart 3.3+** (Flutter **3.19+**).

## Quick start

```bash
dart pub global activate flutter_sast
flutter_sast .                             # scan the current project
```

That's it. You get a console summary plus `flutter_sast_report.html` in the scanned directory.

<details>
<summary>Prefer a dev dependency instead of a global install?</summary>

```yaml
dev_dependencies:
  flutter_sast: ^0.2.0
```

```bash
dart pub get
dart run flutter_sast .
```

</details>

> If `flutter_sast` is not found after activation, add Dart's global bin directory to your `PATH`:
> `export PATH="$PATH:$HOME/.pub-cache/bin"` (add to `~/.zshrc` or `~/.bashrc` to persist).

### Example output

```text
Security Score : 72/100
Risk Level     : HIGH

[HIGH] DART-002  Insecure HTTP URL
  File       : lib/api/client.dart:14
  ...

[MEDIUM] DART-003  SharedPreferences stores sensitive data in cleartext
  File       : lib/auth/storage.dart:22
  ...
```

**Score** (0–100) is a heuristic hygiene indicator (severity × confidence), not CVSS or exploitability. `INFO` and dependency **Recommendation** rows don't lower it.

## What it checks

| Layer | Examples |
|-------|----------|
| **Dart** | Hardcoded secrets; cleartext HTTP / weak TLS; sensitive `SharedPreferences` / `GetStorage`; `FlutterSecureStorage` without Android encryption; weak crypto, injection sinks, unsafe paths; WebView and logging issues |
| **Android** | `AndroidManifest.xml`, `strings.xml` — debuggable builds, backup, cleartext, exported components, permissions |
| **iOS** | `Info.plist` — ATS, file sharing (`--profile privacy` focuses on usage-description strings) |
| **Dependencies** | Debug packages in production deps; secure-storage / pinning advisories (Flutter apps only) |
| **Build & config** | `.env` gitignore, release signing, ProGuard rules |

## Usage

```bash
flutter_sast .                  # scan current directory
flutter_sast scan /path/to/app  # scan a specific project (scan is optional)
flutter_sast --profile privacy  # iOS Info.plist usage-description focus
flutter_sast --profile web      # web checks (CSP, dart:io guard, WebView allowlist)
```

<details>
<summary>All flags</summary>

| Flag | Purpose |
|------|---------|
| `--no-dart` / `--no-android` / `--no-ios` / `--no-pubspec` | Skip that area |
| `--no-env` | Skip `.env` files |
| `--no-web` | Skip `web/index.html` (only used with `--profile web`) |
| `--profile privacy` | iOS `Info.plist` only (includes usage-description checks) |
| `--profile web` | Web CSP, `dart:io` guard, WebView allowlist (`WEB-*`, `DART-010`) |
| `-r DART-001` | Run specific rules only |
| `-e build/` | Extra path prefixes to skip |
| `-o ./reports/` | HTML report output directory or `.html` path |
| `-f console` | Output formats (`console`, `html`; default both) |
| `-q` | Quiet — skip console, write HTML only |

</details>

## Reports

By default you get a console summary **and** `flutter_sast_report.html` in the scanned directory.

```bash
flutter_sast -o ./security/     # write HTML under ./security/
flutter_sast -f console         # console only, no HTML file
flutter_sast -q                 # HTML only, no console
```

Need machine-readable output? Use the [programmatic API](#programmatic-api) — `ScanReport.toJson()` gives you a serializable map.

## CI

```bash
flutter_sast --fail-on-high     # exit 1 on any HIGH or CRITICAL finding
flutter_sast --fail-on-any      # exit 1 on any finding
```

Exit codes: `0` ok · `1` policy/usage error · `2` scan error.

## Configuration

Most projects need none. Add a `.flutter_sast.yml` in the project root only to tune things:

```yaml
exclude:
  glob:
    - "**/*.g.dart"
rules:
  AND-004:
    exported_allowlist:
      - com.example.YourOAuthActivity
profiles:
  default: security
```

- `exported_allowlist` skips **AND-004** for named Android components (e.g. OAuth callback activities).
- Per-rule `severity` and `exclude_globs` override defaults for matching paths.
- Suppress a single line inline: `// flutter_sast:ignore DART-004`

## Rule IDs

Every finding carries a `ruleId` in both the console and HTML reports.

<details>
<summary>ID ranges by area</summary>

| Area | IDs |
|------|-----|
| Dart | `DART-001`–`018` |
| Android | `AND-001`–`015` |
| iOS | `IOS-001`–`006` |
| Dependencies | `DEPS-002`, `003`, `006` |
| Build | `CONFIG-001`, `003`, `004` |
| Web (`--profile web`) | `WEB-001`, `002`, `DART-010` |

Pure Dart CLIs (no `flutter` in `pubspec.yaml`) skip `DEPS-002` / `DEPS-003` advisories.

</details>

## Programmatic API

```dart
import 'package:flutter_sast/flutter_sast.dart';

final report = await FlutterSastScanner().scan('/path/to/app');

ConsoleReporter().report(report);            // console summary
await HtmlReporter().writeReport(report, 'report.html');

final json = report.toJson();                // serializable map for custom output
```

See [`example/main.dart`](example/main.dart).

## Limitations

- Not semantic dataflow analysis — no guarantee a finding is exploitable.
- Not runtime / dynamic (DAST) testing.
- May report false positives; tune with `// flutter_sast:ignore RULE-ID` or `.flutter_sast.yml`.
- Default scan skips `test/`, `build/`, and `example/` paths.

## Links

- [pub.dev package](https://pub.dev/packages/flutter_sast) · [Publisher: umaraslam.dev](https://pub.dev/publishers/umaraslam.dev)
- [Repository](https://github.com/umaraslam-cs/flutter_sast) · [Issues](https://github.com/umaraslam-cs/flutter_sast/issues) · [Changelog](CHANGELOG.md)

Contributing: run `dart test` in the repo root.

MIT — see [LICENSE](LICENSE).
