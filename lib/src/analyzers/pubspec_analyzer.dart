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
    // Cleartext HTTP is reported by [InsecureNetworkRule] when `http://` appears
    // in Dart sources; listing `http` here only duplicates that signal.
    _RiskyDep(
      'dio',
      'Dio certificate validation and interceptor configuration can be '
          'disabled accidentally; audit usage and pin to the latest version.',
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
  ];

  // Any of these packages provides recognised certificate-pinning support.
  static const List<String> _certPinningPackages = <String>[
    'ssl_pinning_plugin',
    'http_certificate_pinning',
    'flutter_certificate_pinning',
  ];

  List<Vulnerability> analyze(
    String content, {
    bool includeAppDependencyAdvisories = true,
    String? libSourceAggregate,
    Set<String> importedPackages = const <String>{},
  }) {
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
          category: 'Recommendation',
          severity: dep.severity,
          cwe: 'CWE-1104',
          owasp: 'M2: Inadequate Supply Chain Security',
          scored: false,
        ));
      }
    }

    if (includeAppDependencyAdvisories) {
      for (final _MissingDep dep in _recommended) {
        if (!declared.contains(dep.name)) {
          final bool usesPlainPrefs = libSourceAggregate != null &&
              RegExp(r'SharedPreferences|shared_preferences')
                  .hasMatch(libSourceAggregate);
          if (!usesPlainPrefs) {
            continue;
          }
          findings.add(Vulnerability(
            ruleId: 'DEPS-002',
            title: 'Recommended security package missing: ${dep.name}',
            description: dep.description,
            recommendation:
                'Add ${dep.name} to dependencies and use it where appropriate.',
            filePath: filePath,
            category: 'Recommendation',
            severity: dep.severity,
            cwe: 'CWE-693',
            owasp: 'M2: Inadequate Supply Chain Security',
            scored: false,
          ));
        }
      }

      final bool hasPinningPackage =
          _certPinningPackages.any((String pkg) => declared.contains(pkg));
      final bool hasInCodePinning = libSourceAggregate != null &&
          RegExp(
            r'validateCertificate|badCertificateCallback.*fingerprint|'
            r'sha256.*compare|certificatePinning',
            caseSensitive: false,
          ).hasMatch(libSourceAggregate);
      if (!hasPinningPackage && !hasInCodePinning) {
        findings.add(Vulnerability(
          ruleId: 'DEPS-003',
          title: 'No certificate-pinning package detected',
          description:
              'None of the recognised certificate-pinning packages '
              '(${_certPinningPackages.join(", ")}) were found, and no in-code '
              'pinning pattern was detected in lib/.',
          recommendation:
              'Add a certificate-pinning package and configure it for '
              'your critical API hosts.',
          filePath: filePath,
          category: 'Recommendation',
          severity: Severity.low,
          cwe: 'CWE-295',
          owasp: 'M3: Insecure Communication',
          scored: false,
        ));
      }

      const List<String> securityPackages = <String>[
        'flutter_jailbreak_detection',
        'flutter_jailbreak_detection_plus',
        'safe_device',
      ];
      for (final String pkg in securityPackages) {
        if (declared.contains(pkg) && !importedPackages.contains(pkg)) {
          findings.add(Vulnerability(
            ruleId: 'DEPS-004',
            title: 'Security dependency declared but unused: $pkg',
            description:
                '$pkg is in pubspec.yaml but no import was found under lib/.',
            recommendation: 'Wire up the control or remove the unused dependency.',
            filePath: filePath,
            category: 'Recommendation',
            severity: Severity.info,
            cwe: 'CWE-1104',
            owasp: 'M2: Inadequate Supply Chain Security',
            scored: false,
          ));
        }
      }
    }

    // Note: --obfuscate / --split-debug-info are flutter build CLI flags, not
    // pubspec entries, so they cannot be reliably detected here. Users should
    // add these flags to their CI/CD build scripts.

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
