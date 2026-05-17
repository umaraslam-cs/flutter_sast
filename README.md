# flutter_sast

[![Dart SDK](https://img.shields.io/badge/sdk-%3E%3D2.17.0-brightgreen)](https://dart.dev/get-dart)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**flutter_sast** is a static application security testing (SAST) and vulnerability assessment tool for **Flutter** and **Dart** projects. It scans Dart source, `AndroidManifest.xml`, `ios/Runner/Info.plist`, and `pubspec.yaml`, then prints a console summary and writes `flutter_sast_report.json` and `flutter_sast_report.html` in the project directory (one command, no extra flags).

The package targets **Dart SDK 2.17+**, which matches **Flutter 3.0.0** (Dart 2.17) and all newer stable Flutter releases whose Dart version stays below 4.0.

> This package is a **heuristic** scanner: it flags patterns that *often* indicate risk. Review each finding in context before changing code or treating results as a full penetration test.

## Features

- **Dart rules** — hardcoded secrets, cleartext HTTP, permissive TLS callbacks, insecure local storage, weak crypto (MD5, SHA-1, ECB, insecure `Random`, hardcoded IVs), SQL injection sinks, path traversal, mirrors, WebView JS mode, clipboard misuse, and weak biometric options.
- **Android** — debuggable release builds, backup, cleartext traffic, exported components, storage permissions, boot receiver, missing network security config.
- **iOS** — App Transport Security relaxations, file sharing flags, sensitive usage-description keys.
- **Dependencies** — risky packages, secure-storage recommendations, and certificate-pinning advisories.
- **Outputs** — colored console, pretty JSON, dark-themed HTML (no external assets).

## Install

### Global CLI (recommended)

```bash
dart pub global activate flutter_sast
```

Add the Dart global bin directory to your `PATH` (once per machine, or add to `~/.zshrc` / `~/.bashrc`):

```bash
export PATH="$PATH:$HOME/.pub-cache/bin"
```

On Windows (PowerShell), add `%LOCALAPPDATA%\Pub\Cache\bin` to your user `Path` environment variable, then open a new terminal.

Verify: `flutter_sast -v`

### As a dev dependency

Add to your app’s `pubspec.yaml`:

```yaml
dev_dependencies:
  flutter_sast: ^0.1.0
```

Then:

```bash
dart pub get
dart run flutter_sast scan
# or pass the project root explicitly:
dart run flutter_sast scan /path/to/your/flutter_app
```

Arguments after `flutter_sast` are forwarded to the executable; use `--` if your shell needs it:

```bash
dart run flutter_sast -- scan .
```

## Usage

From your **Flutter project root** (where `pubspec.yaml` lives):

```bash
flutter_sast
# same as:
flutter_sast scan
flutter_sast .
```

That prints a **console** summary and writes **`flutter_sast_report.json`** and **`flutter_sast_report.html`** in the project directory.

Scan another tree:

```bash
flutter_sast /path/to/your/flutter_app
# or: flutter_sast scan /path/to/your/flutter_app
```

Print the tool version (no subcommand):

```bash
flutter_sast -v
flutter_sast --version
```

### Reports

By default, every scan produces all three outputs (no extra flags).

```bash
flutter_sast               # console + flutter_sast_report.json + .html
flutter_sast .             # same
```

Optional:

```bash
# CI: files only (no console); JSON/HTML still written
flutter_sast -q

# JSON only
flutter_sast -f json

# Both reports under ./security/ (directory)
flutter_sast -o ./security/

# Shared basename → security/audit.json and security/audit.html
flutter_sast -o ./security/audit

# Single HTML path; JSON lands in the same folder
flutter_sast -o ./security/report.html
```

When stdout is not a terminal (piped or CI), the console summary is skipped automatically; use `-f console` to force it.

### Scope and CI

All flags below apply to the **`scan`** command (see `flutter_sast scan --help`).

| Flag | Purpose |
|------|---------|
| `--no-dart` | Skip `.dart` file scanning |
| `--no-android` | Skip `android/app/src/main/AndroidManifest.xml` |
| `--no-ios` | Skip `ios/Runner/Info.plist` |
| `--no-pubspec` | Skip `pubspec.yaml` dependency checks |
| `-e`, `--exclude` | Extra path prefixes to skip (repeatable) |
| `-r`, `--rules` | Run only given rule IDs, e.g. `-r DART-001` |
| `-q`, `--quiet` | Skip console output (file reports only) |
| `--fail-on-high` | Exit `1` if any **HIGH** or **CRITICAL** finding |
| `--fail-on-any` | Exit `1` if any finding |

Exit codes: `0` success, `1` policy failure (`--fail-on-*`) or usage error, `2` scan error (e.g. invalid project path).

## Programmatic API

```dart
import 'package:flutter_sast/flutter_sast.dart';

Future<void> main() async {
  const options = ScanOptions();
  final report = await FlutterSastScanner(options: options).scan('/path/to/app');

  ConsoleReporter().report(report);
  await JsonReporter().writeReport(report, 'report.json');
  await HtmlReporter().writeReport(report, 'report.html');
}
```

See [`example/main.dart`](example/main.dart) for a runnable sample (`cd example && dart pub get && dart run`).

## Development

```bash
dart pub get
dart analyze
dart test
dart pub publish --dry-run   # before publishing
```

## Links

- **Repository:** [github.com/umaraslam-cs/flutter_sast](https://github.com/umaraslam-cs/flutter_sast)
- **Issues:** [github.com/umaraslam-cs/flutter_sast/issues](https://github.com/umaraslam-cs/flutter_sast/issues)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE).
