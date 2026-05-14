// lib/src/analyzers/pubspec_analyzer.dart

import 'package:yaml/yaml.dart';

import '../models/severity.dart';
import '../models/vulnerability.dart';

class _RiskyDep {
  final String name;
  final String description;
  final Severity severity;
  const _RiskyDep(this.name, this.description, this.severity);
}

class _MissingDep {
  final String name;
  final String description;
  final Severity severity;
  const _MissingDep(this.name, this.description, this.severity);
}

/// Analyzes the `pubspec.yaml` for risky packages and missing protections.
class PubspecAnalyzer {
  static const String filePath = 'pubspec.yaml';
  static const String _category = 'Dependencies';

  static const List<_RiskyDep> _risky = <_RiskyDep>[
    _RiskyDep(
      'http',
      'Versions below 1.0.0 lack TLS security improvements',
      Severity.low,
    ),
    _RiskyDep(
      'dio',
      'Versions below 5.x have certificate validation issues',
      Severity.low,
    ),
    _RiskyDep(
      'get_storage',
      'Stores data as plaintext JSON',
      Severity.info,
    ),
    _RiskyDep(
      'sqflite',
      'Databases unencrypted by default',
      Severity.info,
    ),
    _RiskyDep(
      'shared_preferences',
      'Stores data as plaintext',
      Severity.info,
    ),
  ];

  static const List<_MissingDep> _recommended = <_MissingDep>[
    _MissingDep(
      'flutter_secure_storage',
      'No secure storage package detected. Sensitive values are likely '
          'persisted in plaintext.',
      Severity.medium,
    ),
    _MissingDep(
      'ssl_pinning_plugin',
      'No certificate pinning package detected. Consider pinning the TLS '
          'certificate / public key for critical endpoints.',
      Severity.low,
    ),
  ];

  List<Vulnerability> analyze(String content) {
    final List<Vulnerability> findings = <Vulnerability>[];

    Set<String> declared;
    try {
      final dynamic doc = loadYaml(content);
      declared = _collectKeys(doc);
    } on YamlException {
      declared = <String>{};
    }

    for (final _RiskyDep dep in _risky) {
      if (declared.contains(dep.name)) {
        findings.add(Vulnerability(
          ruleId: 'DEPS-001',
          title: 'Risky dependency: ${dep.name}',
          description: dep.description,
          recommendation:
              'Audit usage of ${dep.name}, pin to the latest version, or '
              'replace with a more secure alternative.',
          filePath: filePath,
          category: _category,
          severity: dep.severity,
          cwe: 'CWE-1104',
          owasp: 'M2: Inadequate Supply Chain Security',
        ));
      }
    }

    for (final _MissingDep dep in _recommended) {
      if (!declared.contains(dep.name)) {
        findings.add(Vulnerability(
          ruleId: 'DEPS-002',
          title: 'Recommended security package missing: ${dep.name}',
          description: dep.description,
          recommendation:
              'Add ${dep.name} to dependencies and use it where appropriate.',
          filePath: filePath,
          category: _category,
          severity: dep.severity,
          cwe: 'CWE-693',
          owasp: 'M2: Inadequate Supply Chain Security',
        ));
      }
    }

    final bool hasObfuscation =
        content.contains('obfuscate') || content.contains('split-debug-info');
    if (!hasObfuscation) {
      findings.add(const Vulnerability(
        ruleId: 'DEPS-003',
        title: 'Release builds do not appear to use obfuscation',
        description:
            'No reference to --obfuscate or --split-debug-info was found in '
            'pubspec.yaml. Without obfuscation, Dart symbols are easy to '
            'recover from a release build.',
        recommendation:
            'Build releases with `flutter build apk --obfuscate '
            '--split-debug-info=build/debug-info`.',
        filePath: filePath,
        category: _category,
        severity: Severity.low,
        cwe: 'CWE-693',
        owasp: 'M7: Client Code Quality',
      ));
    }

    return findings;
  }

  Set<String> _collectKeys(dynamic doc) {
    final Set<String> result = <String>{};
    if (doc is! YamlMap) {
      return result;
    }
    _addKeys(doc['dependencies'], result);
    _addKeys(doc['dev_dependencies'], result);
    return result;
  }

  void _addKeys(dynamic node, Set<String> sink) {
    if (node is YamlMap) {
      for (final dynamic key in node.keys) {
        if (key is String) {
          sink.add(key);
        }
      }
    }
  }
}
