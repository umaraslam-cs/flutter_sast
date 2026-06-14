# flutter_sast

[![Dart SDK](https://img.shields.io/badge/sdk-%3E%3D3.3.0-brightgreen)](https://dart.dev/get-dart)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**flutter_sast** is a lightweight static scanner for **Flutter** and **Dart** projects. It looks for common security misconfigurations and risky patterns in app code, platform files, and dependencies. One command prints a summary and writes `flutter_sast_report.html`.

Requires **Dart 3.3+** (Flutter **3.19+**).

> **How it works:** regex and line-based heuristics — not a full AST analyzer or penetration test. Review every finding in context.

### Limitations

- Not semantic dataflow analysis; no guarantee a finding is exploitable
- Not runtime / dynamic (DAST) testing
- May report false positives; use `// flutter_sast:ignore RULE-ID` or `.flutter_sast.yml` to tune
- Default scan skips `test/`, `build/`, and `example/` paths

## What it checks

| Layer | Examples |
|-------|----------|
| **Dart** | Hardcoded secrets; cleartext HTTP / weak TLS; sensitive `SharedPreferences` / `GetStorage`; `FlutterSecureStorage` without Android encryption; patterns suggesting weak crypto, injection sinks, or unsafe paths; WebView and logging issues |
| **Android** | `AndroidManifest.xml`, `strings.xml` — debuggable builds, backup, cleartext, exported components, permissions |
| **iOS** | `Info.plist` — ATS, file sharing (`--profile privacy` focuses on usage-description strings) |
| **Dependencies** | Debug packages in production deps; secure-storage / pinning advisories (Flutter apps only) |
| **Build & config** | `.env` gitignore, release signing, ProGuard rules |

## Install

```bash
dart pub global activate flutter_sast
export PATH="$PATH:$HOME/.pub-cache/bin"   # add to ~/.zshrc to persist
flutter_sast -v
```

Or as a dev dependency:

```yaml
dev_dependencies:
  flutter_sast: ^0.1.1
```

```bash
dart pub get
dart run flutter_sast .
```

## Quick start

From your project root (where `pubspec.yaml` lives):

```bash
flutter_sast .
```

The `scan` subcommand is optional — these are equivalent:

```bash
flutter_sast .
flutter_sast scan .
flutter_sast scan /path/to/app
```

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

### CI

```bash
flutter_sast -q                      # HTML report only, no console
flutter_sast --fail-on-high          # exit 1 on HIGH/CRITICAL
flutter_sast --fail-on-any           # exit 1 on any finding
```

| Flag | Purpose |
|------|---------|
| `--no-dart` / `--no-android` / `--no-ios` / `--no-pubspec` | Skip that area |
| `--no-env` | Skip `.env` files |
| `--profile privacy` | iOS `Info.plist` only (includes usage-description checks) |
| `--profile web` | Web CSP, `dart:io` guard, WebView allowlist (`WEB-*`, `DART-010`) |
| `--no-web` | Skip `web/index.html` (only used with `--profile web`) |
| `-r DART-001` | Run specific rules only |
| `-e build/` | Extra paths to skip |
| `-o ./reports/` | HTML report output directory or `.html` path |

Exit codes: `0` ok, `1` policy/usage error, `2` scan error.

### Optional config

Create `.flutter_sast.yml` in the project root only if you need tuning:

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

`exported_allowlist` skips **AND-004** for named Android components (e.g. OAuth callback activities). Per-rule `severity` and `exclude_globs` override defaults for matching paths.

Suppress a line: `// flutter_sast:ignore DART-004`

More options: [CHANGELOG.md](CHANGELOG.md).

## Reports

Default: console + `flutter_sast_report.html` in the **scanned project** directory.

```bash
flutter_sast -o ./security/           # HTML report under ./security/
flutter_sast -f console               # console only, no HTML file
```

**Score** (0–100) is a heuristic hygiene indicator (severity × confidence), not CVSS or exploitability. `INFO` and dependency **Recommendation** rows do not lower the score.

## Rule IDs (summary)

Each finding includes a `ruleId` in both console and HTML reports.

| Area | IDs |
|------|-----|
| Dart | `DART-001`–`018` |
| Android | `AND-001`–`015` |
| iOS | `IOS-001`–`006` |
| Dependencies | `DEPS-002`, `003`, `006` |
| Build | `CONFIG-001`, `003`, `004` |
| Web (`--profile web`) | `WEB-001`, `002`, `DART-010` |

Pure Dart CLIs (no `flutter` in `pubspec.yaml`) skip `DEPS-002` / `DEPS-003` advisories.

## API

```dart
import 'package:flutter_sast/flutter_sast.dart';

final report = await FlutterSastScanner().scan('/path/to/app');
ConsoleReporter().report(report);
```

See [`example/main.dart`](example/main.dart).

## Links

- [pub.dev package](https://pub.dev/packages/flutter_sast)
- [Publisher: umaraslam.dev](https://pub.dev/publishers/umaraslam.dev)
- [Repository](https://github.com/umaraslam-cs/flutter_sast) (contributing: `dart test` in repo root)
- [Issues](https://github.com/umaraslam-cs/flutter_sast/issues)
- [Changelog](CHANGELOG.md)

MIT — see [LICENSE](LICENSE).
