// lib/src/scanner.dart

import 'dart:io';

import 'package:path/path.dart' as p;

import 'analyzers/android_manifest_analyzer.dart';
import 'analyzers/ios_plist_analyzer.dart';
import 'analyzers/pubspec_analyzer.dart';
import 'models/report.dart';
import 'models/vulnerability.dart';
import 'rules/base_rule.dart';
import 'rules/dart/code_security_rule.dart';
import 'rules/dart/hardcoded_secrets_rule.dart';
import 'rules/dart/insecure_network_rule.dart';
import 'rules/dart/insecure_storage_rule.dart';
import 'rules/dart/weak_crypto_rule.dart';

/// User-facing scanner configuration.
class ScanOptions {
  final bool includeDart;
  final bool includeAndroid;
  final bool includeIos;
  final bool includePubspec;
  final List<String> excludePaths;
  final List<String> ruleIds;

  const ScanOptions({
    this.includeDart = true,
    this.includeAndroid = true,
    this.includeIos = true,
    this.includePubspec = true,
    this.excludePaths = const <String>[
      'build/',
      '.dart_tool/',
      '.pub-cache/',
      'test/',
    ],
    this.ruleIds = const <String>[],
  });
}

/// Walks a Flutter / Dart project and runs every configured rule and
/// analyzer, returning a single aggregated [ScanReport].
class FlutterSastScanner {
  final ScanOptions options;
  final List<FilePatternRule> _dartRules;

  FlutterSastScanner({ScanOptions? options})
      : options = options ?? const ScanOptions(),
        _dartRules = <FilePatternRule>[
          HardcodedSecretsRule(),
          InsecureNetworkRule(),
          InsecureStorageRule(),
          WeakCryptoRule(),
          CodeSecurityRule(),
        ];

  Future<ScanReport> scan(String projectPath) async {
    final Directory root = Directory(projectPath);
    if (!await root.exists()) {
      throw ArgumentError(
        'Project path does not exist: $projectPath',
      );
    }

    final Stopwatch sw = Stopwatch()..start();
    final List<Vulnerability> findings = <Vulnerability>[];
    int filesScanned = 0;

    if (options.includeDart) {
      await for (final FileSystemEntity entity
          in root.list(recursive: true, followLinks: false)) {
        if (entity is! File) {
          continue;
        }
        if (!entity.path.endsWith('.dart')) {
          continue;
        }
        final String relative = p.relative(entity.path, from: projectPath);
        if (_isExcluded(relative)) {
          continue;
        }

        String content;
        try {
          content = await entity.readAsString();
        } on FileSystemException {
          continue;
        }
        if (content.isEmpty) {
          continue;
        }

        filesScanned += 1;
        for (final FilePatternRule rule in _dartRules) {
          if (!rule.appliesTo(relative)) {
            continue;
          }
          if (!_ruleEnabled(rule.ruleId)) {
            continue;
          }
          final List<Vulnerability> ruleFindings =
              rule.analyze(relative, content);
          if (options.ruleIds.isEmpty) {
            findings.addAll(ruleFindings);
          } else {
            findings.addAll(
              ruleFindings.where(
                (Vulnerability v) => _subRuleEnabled(v.ruleId),
              ),
            );
          }
        }
      }
    }

    if (options.includeAndroid) {
      final File manifest = File(
        p.join(projectPath, 'android', 'app', 'src', 'main', 'AndroidManifest.xml'),
      );
      if (await manifest.exists()) {
        final String content = await manifest.readAsString();
        _addFiltered(findings, AndroidManifestAnalyzer().analyze(content));
      }
    }

    if (options.includeIos) {
      final File plist = File(
        p.join(projectPath, 'ios', 'Runner', 'Info.plist'),
      );
      if (await plist.exists()) {
        final String content = await plist.readAsString();
        _addFiltered(findings, IosPlistAnalyzer().analyze(content));
      }
    }

    if (options.includePubspec) {
      final File pubspec = File(p.join(projectPath, 'pubspec.yaml'));
      if (await pubspec.exists()) {
        final String content = await pubspec.readAsString();
        _addFiltered(findings, PubspecAnalyzer().analyze(content));
      }
    }

    findings.sort(
      (Vulnerability a, Vulnerability b) =>
          b.severity.score.compareTo(a.severity.score),
    );

    sw.stop();

    return ScanReport(
      projectPath: projectPath,
      scannedAt: DateTime.now(),
      vulnerabilities: findings,
      filesScanned: filesScanned,
      scanDuration: sw.elapsed,
    );
  }

  /// Appends [incoming] to [sink], applying the `--rules` filter when active.
  ///
  /// Used for both Dart rule findings and platform-analyzer findings so that
  /// `--rules AND-001` suppresses IOS/DEPS findings, and vice-versa.
  void _addFiltered(List<Vulnerability> sink, List<Vulnerability> incoming) {
    if (options.ruleIds.isEmpty) {
      sink.addAll(incoming);
    } else {
      sink.addAll(incoming.where((Vulnerability v) => _subRuleEnabled(v.ruleId)));
    }
  }

  /// [excludePaths] entries are matched as path prefixes (not segments), so
  /// `'test/'` also excludes `'test_helpers/'`. Callers should use trailing
  /// slashes to reduce unintended matches.
  bool _isExcluded(String relativePath) {
    final String normalized = relativePath.replaceAll('\\', '/');
    for (final String exclude in options.excludePaths) {
      if (normalized.startsWith(exclude)) {
        return true;
      }
    }
    return false;
  }

  /// Pre-flight check: should we even run this rule?
  ///
  /// Runs the rule when [ruleIds] is empty, when a requested ID equals this
  /// rule's ID, or when a requested ID is a sub-rule of it
  /// (e.g. `--rules DART-002b` still runs the `DART-002` rule class).
  /// Intentionally does NOT match partial prefixes like `DART-0`.
  bool _ruleEnabled(String ruleId) {
    if (options.ruleIds.isEmpty) return true;
    return options.ruleIds.any(
      (String id) => id == ruleId || id.startsWith(ruleId),
    );
  }

  /// Post-analysis filter: does this specific finding's ID match the filter?
  ///
  /// Accepts exact matches and parent-prefix matches so `--rules DART-002`
  /// includes sub-rule findings `DART-002b`, `DART-002c`, etc.
  bool _subRuleEnabled(String ruleId) {
    if (options.ruleIds.isEmpty) return true;
    return options.ruleIds.any(
      (String id) => ruleId == id || ruleId.startsWith(id),
    );
  }
}
