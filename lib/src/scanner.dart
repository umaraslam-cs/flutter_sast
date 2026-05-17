// lib/src/scanner.dart

import 'dart:io';

import 'package:path/path.dart' as p;

import 'analyzers/android_manifest_analyzer.dart';
import 'analyzers/config_analyzer.dart';
import 'analyzers/env_analyzer.dart';
import 'analyzers/ios_plist_analyzer.dart';
import 'analyzers/pubspec_analyzer.dart';
import 'analyzers/strings_xml_analyzer.dart';
import 'analyzers/web_index_analyzer.dart';
import 'config/sast_config.dart';
import 'models/report.dart';
import 'models/vulnerability.dart';
import 'project_info.dart';
import 'rules/base_rule.dart';
import 'rules/dart/code_security_rule.dart';
import 'rules/dart/dart_io_web_rule.dart';
import 'rules/dart/hardcoded_credentials_rule.dart';
import 'rules/dart/hardcoded_secrets_rule.dart';
import 'rules/dart/insecure_network_rule.dart';
import 'rules/dart/insecure_storage_rule.dart';
import 'rules/dart/production_debug_rule.dart';
import 'rules/dart/sensitive_logging_rule.dart';
import 'rules/dart/tls_pinning_rule.dart';
import 'rules/dart/weak_crypto_rule.dart';
import 'rules/dart/webview_security_rule.dart';

/// User-facing scanner configuration.
class ScanOptions {
  final bool includeDart;
  final bool includeAndroid;
  final bool includeIos;
  final bool includePubspec;
  final bool includeWeb;
  final bool includeEnv;
  final List<String> excludePaths;
  final List<String> ruleIds;
  final String profile;

  const ScanOptions({
    this.includeDart = true,
    this.includeAndroid = true,
    this.includeIos = true,
    this.includePubspec = true,
    this.includeWeb = true,
    this.includeEnv = true,
    this.excludePaths = const <String>[
      'build/',
      '.dart_tool/',
      '.pub-cache/',
      'test/',
      'example/',
    ],
    this.ruleIds = const <String>[],
    this.profile = 'security',
  });
}

/// Walks a Flutter / Dart project and runs every configured rule and
/// analyzer, returning a single aggregated [ScanReport].
class FlutterSastScanner {
  final ScanOptions options;

  FlutterSastScanner({ScanOptions? options}) : options = options ?? const ScanOptions();

  Future<ScanReport> scan(String projectPath) async {
    final ProjectInfo project = await ProjectInfo.resolve(projectPath);
    final Directory root = Directory(project.path);
    if (!await root.exists()) {
      throw ArgumentError(
        'Project path does not exist: ${project.path}',
      );
    }

    final SastConfig config = await SastConfig.load(project.path);
    final String profile =
        options.profile.isNotEmpty ? options.profile : config.profile;
    final bool includePrivacy = profile == 'privacy';
    final bool includeWebProfile = profile == 'web';
    final List<FilePatternRule> dartRules = _buildDartRules(config, includeWebProfile);

    final Stopwatch sw = Stopwatch()..start();
    final List<Vulnerability> findings = <Vulnerability>[];
    int filesScanned = 0;
    final StringBuffer libAggregate = StringBuffer();

    if (options.includeDart) {
      await for (final FileSystemEntity entity
          in root.list(recursive: true, followLinks: false)) {
        if (entity is! File || !entity.path.endsWith('.dart')) {
          continue;
        }
        final String relative = p.relative(entity.path, from: project.path);
        if (_isExcluded(relative, config)) {
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

        if (relative.startsWith('lib/')) {
          libAggregate.writeln(content);
        }

        filesScanned += 1;
        for (final FilePatternRule rule in dartRules) {
          if (!rule.appliesTo(relative)) {
            continue;
          }
          if (project.name == 'flutter_sast' &&
              rule.shouldSkipRuleImplementationFile(relative)) {
            continue;
          }
          if (!_ruleEnabled(rule.ruleId)) {
            continue;
          }
          if (config.ruleExcludedForPath(rule.ruleId, relative)) {
            continue;
          }
          final List<Vulnerability> ruleFindings =
              rule.analyze(relative, content);
          final List<Vulnerability> filtered = _applyProfile(
            _applySuppressions(ruleFindings, content),
            profile,
          );
          if (options.ruleIds.isEmpty) {
            findings.addAll(filtered);
          } else {
            findings.addAll(
              filtered.where(
                (Vulnerability v) => _subRuleEnabled(v.ruleId),
              ),
            );
          }
        }
      }
    }

    if (options.includeEnv) {
      await for (final FileSystemEntity entity
          in root.list(recursive: true, followLinks: false)) {
        if (entity is! File) {
          continue;
        }
        final String relative = p.relative(entity.path, from: project.path);
        final String name = p.basename(entity.path);
        if (!name.startsWith('.env') && !relative.contains('/env/')) {
          continue;
        }
        if (_isExcluded(relative, config)) {
          continue;
        }
        String content;
        try {
          content = await entity.readAsString();
        } on FileSystemException {
          continue;
        }
        _addFiltered(findings, EnvAnalyzer().analyze(relative, content), profile);
      }
    }

    if (options.includeAndroid) {
      final File manifest = File(
        p.join(project.path, AndroidManifestAnalyzer.filePath),
      );
      if (await manifest.exists()) {
        _addFiltered(
          findings,
          AndroidManifestAnalyzer(
            exportedAllowlist: config.exportedAllowlist,
          ).analyze(await manifest.readAsString()),
          profile,
        );
      }

      final Directory valuesDir = Directory(
        p.join(project.path, 'android', 'app', 'src', 'main', 'res'),
      );
      if (await valuesDir.exists()) {
        await for (final FileSystemEntity entity
            in valuesDir.list(recursive: true)) {
          if (entity is! File || !entity.path.endsWith('strings.xml')) {
            continue;
          }
          final String relative =
              p.relative(entity.path, from: project.path);
          _addFiltered(
            findings,
            StringsXmlAnalyzer().analyze(
              relative,
              await entity.readAsString(),
            ),
            profile,
          );
        }
      }
    }

    if (options.includeIos) {
      final File plist = File(
        p.join(project.path, IosPlistAnalyzer.filePath),
      );
      if (await plist.exists()) {
        _addFiltered(
          findings,
          IosPlistAnalyzer(includePrivacyKeys: includePrivacy)
              .analyze(await plist.readAsString()),
          profile,
        );
      }
    }

    if (options.includePubspec) {
      final File pubspec = File(p.join(project.path, 'pubspec.yaml'));
      if (await pubspec.exists()) {
        _addFiltered(
          findings,
          PubspecAnalyzer().analyze(
            await pubspec.readAsString(),
            includeAppDependencyAdvisories: project.isFlutterApplication,
            libSourceAggregate: libAggregate.toString(),
          ),
          profile,
        );
      }
    }

    if (options.includeWeb && includeWebProfile) {
      final File index = File(p.join(project.path, WebIndexAnalyzer.filePath));
      if (await index.exists()) {
        _addFiltered(
          findings,
          WebIndexAnalyzer().analyze(await index.readAsString()),
          profile,
        );
      }
    }

    _addFiltered(findings, ConfigAnalyzer().analyze(project.path), profile);

    _dedupeFindings(findings);

    findings.sort(
      (Vulnerability a, Vulnerability b) =>
          b.severity.score.compareTo(a.severity.score),
    );

    sw.stop();

    return ScanReport(
      projectPath: project.path,
      projectName: project.name,
      scannedAt: DateTime.now(),
      vulnerabilities: findings,
      filesScanned: filesScanned,
      scanDuration: sw.elapsed,
    );
  }

  static List<FilePatternRule> _buildDartRules(
    SastConfig config,
    bool includeWebProfile,
  ) {
    final List<FilePatternRule> rules = <FilePatternRule>[
      HardcodedSecretsRule(),
      HardcodedCredentialsRule(),
      InsecureNetworkRule(),
      TlsPinningRule(),
      InsecureStorageRule(),
      SensitiveLoggingRule(),
      WeakCryptoRule(),
      CodeSecurityRule(),
      WebViewSecurityRule(allowedHosts: config.webviewAllowedHosts),
      ProductionDebugRule(),
    ];
    if (includeWebProfile) {
      rules.add(DartIoWebRule());
    }
    return rules;
  }

  List<Vulnerability> _applyProfile(
    List<Vulnerability> incoming,
    String profile,
  ) {
    if (profile == 'privacy') {
      return incoming
          .where((Vulnerability v) => v.ruleId.startsWith('IOS-'))
          .toList();
    }
    if (profile == 'web') {
      return incoming
          .where((Vulnerability v) =>
              v.ruleId.startsWith('WEB-') || v.ruleId == 'DART-010')
          .toList();
    }
    return incoming
        .where((Vulnerability v) => v.ruleId != 'IOS-006')
        .toList();
  }

  List<Vulnerability> _applySuppressions(
    List<Vulnerability> incoming,
    String fileContent,
  ) {
    final Set<String> ignoredRules = <String>{};
    for (final RegExpMatch m in inlineIgnorePattern.allMatches(fileContent)) {
      ignoredRules.add(m.group(1)!.toUpperCase());
    }
    return incoming
        .where((Vulnerability v) => !ignoredRules.contains(v.ruleId))
        .toList();
  }

  void _dedupeFindings(List<Vulnerability> findings) {
    final Map<String, Vulnerability> unique = <String, Vulnerability>{};
    for (final Vulnerability v in findings) {
      final String key =
          '${v.ruleId}|${v.filePath}|${v.lineNumber ?? 0}';
      final Vulnerability? existing = unique[key];
      if (existing == null ||
          v.severity.score > existing.severity.score) {
        unique[key] = v;
      }
    }
    findings
      ..clear()
      ..addAll(unique.values);
  }

  void _addFiltered(
    List<Vulnerability> sink,
    List<Vulnerability> incoming,
    String profile,
  ) {
    final List<Vulnerability> filtered = _applyProfile(incoming, profile);
    if (options.ruleIds.isEmpty) {
      sink.addAll(filtered);
    } else {
      sink.addAll(
        filtered.where((Vulnerability v) => _subRuleEnabled(v.ruleId)),
      );
    }
  }

  bool _isExcluded(String relativePath, SastConfig config) {
    final String normalized = relativePath.replaceAll('\\', '/');
    if (config.isExcludedPath(normalized)) {
      return true;
    }
    for (final String exclude in options.excludePaths) {
      if (normalized.startsWith(exclude)) {
        return true;
      }
    }
    return false;
  }

  bool _ruleEnabled(String ruleId) {
    if (options.ruleIds.isEmpty) return true;
    return options.ruleIds.any(
      (String id) =>
          ruleIdMatchesFilter(id, ruleId) || ruleIdMatchesFilter(ruleId, id),
    );
  }

  bool _subRuleEnabled(String ruleId) {
    if (options.ruleIds.isEmpty) return true;
    return options.ruleIds.any(
      (String id) => ruleIdMatchesFilter(ruleId, id),
    );
  }
}
