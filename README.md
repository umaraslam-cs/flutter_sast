# flutter_sast

[![Dart SDK](https://img.shields.io/badge/sdk-%3E%3D3.3.0-brightgreen)](https://dart.dev/get-dart)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**flutter_sast** scans **Flutter** and **Dart** projects for common security issues: hardcoded secrets, weak crypto, insecure storage, Android/iOS misconfigurations, and dependency risks. One command writes a console summary plus `flutter_sast_report.json` and `flutter_sast_report.html`.

Requires **Dart 3.3+** (Flutter **3.19+**).

> Heuristic pattern matching — not a full AST or penetration test. Review findings in context.

## What it checks

- **Dart** — secrets, HTTP/TLS, `SharedPreferences` / `GetStorage`, `FlutterSecureStorage` encryption, weak crypto, SQLi sinks, path traversal, WebView, logging, query-param secrets, and more.
- **Android** — `AndroidManifest.xml`, `strings.xml` (debuggable, backup, cleartext, exported components, permissions).
- **iOS** — `Info.plist` (ATS, file sharing, usage descriptions with `--profile privacy`).
- **Dependencies** — debug packages in prod deps; secure-storage / pinning advisories for Flutter apps.
- **Config** — `.env` gitignore, release signing, ProGuard rules.

## Install

```bash
dart pub global activate flutter_sast
export PATH="$PATH:$HOME/.pub-cache/bin"   # add to ~/.zshrc to persist
flutter_sast -v
```

Or as a dev dependency:

```yaml
dev_dependencies:
  flutter_sast: ^0.1.0
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

Same as `flutter_sast scan` or `flutter_sast scan /path/to/app`.

### CI

```bash
flutter_sast -q -f json              # JSON only, no console
flutter_sast --fail-on-high          # exit 1 on HIGH/CRITICAL
flutter_sast --fail-on-any           # exit 1 on any finding
```

| Flag | Purpose |
|------|---------|
| `--no-dart` / `--no-android` / `--no-ios` / `--no-pubspec` | Skip that area |
| `--no-env` | Skip `.env` files |
| `--profile privacy` | iOS usage-description checks |
| `--profile web` | Web CSP + `dart:io` checks |
| `-r DART-001` | Run specific rules only |
| `-e build/` | Extra paths to skip |
| `-o ./reports/` | Report output directory |

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

Suppress a line: `// flutter_sast:ignore DART-004`

Advanced options (`severity`, `exclude_globs`, custom profiles) are documented in [CHANGELOG.md](CHANGELOG.md).

## Reports

Default: console + `flutter_sast_report.json` + `flutter_sast_report.html` in the project directory.

```bash
flutter_sast -f json -o ./security/   # JSON under ./security/
```

**Score** (0–100) is a hygiene hint from finding severity × confidence — not exploitability. `INFO` and dependency **Recommendation** rows do not lower the score.

## Rule IDs (summary)

| Area | IDs |
|------|-----|
| Dart | `DART-001`–`018` (secrets, network, storage, crypto, code quality) |
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

## Development

```bash
dart pub get && dart analyze && dart test
dart pub publish --dry-run
```

## Links

- [Repository](https://github.com/umaraslam-cs/flutter_sast)
- [Issues](https://github.com/umaraslam-cs/flutter_sast/issues)
- [Changelog](CHANGELOG.md)

MIT — see [LICENSE](LICENSE).
