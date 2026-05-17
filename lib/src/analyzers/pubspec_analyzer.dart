// lib/src/analyzers/pubspec_analyzer.dart

import 'package:yaml/yaml.dart';

import '../models/severity.dart';
import '../models/vulnerability.dart';

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
  }) {
    final List<Vulnerability> findings = <Vulnerability>[];

    Set<String> declared;
    try {
      final dynamic doc = loadYaml(content);
      declared = _collectKeys(doc);
    } on YamlException {
      declared = <String>{};
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
            r'sha256.*compare|certificatePinning|SecurityContext|'
            r'pinnedCertificates|setTrustedCertificates',
            caseSensitive: false,
          ).hasMatch(libSourceAggregate);
      if (!hasPinningPackage && !hasInCodePinning) {
        findings.add(Vulnerability(
          ruleId: 'DEPS-003',
          title: 'No certificate-pinning package detected',
          description:
              'None of the recognised certificate-pinning packages '
              '(${_certPinningPackages.join(", ")}) were found, and no in-code '
              'pinning pattern was detected in lib/. Many apps omit pinning; '
              'treat this as a best-practice advisory.',
          recommendation:
              'Consider certificate pinning for high-value API hosts if '
              'threat model requires it.',
          filePath: filePath,
          category: 'Recommendation',
          severity: Severity.info,
          cwe: 'CWE-295',
          owasp: 'M3: Insecure Communication',
          scored: false,
        ));
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
