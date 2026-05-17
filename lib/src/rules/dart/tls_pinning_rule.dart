// lib/src/rules/dart/tls_pinning_rule.dart

import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-002e` — TLS pinning gated only behind remote config flags.
class TlsPinningRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-002';

  @override
  String get title => 'TLS pinning configuration';

  @override
  String get category => 'Network Security';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M3: Insecure Communication';

  static final RegExp _remoteSslGate = RegExp(
    r'\b(?:enableSSL|enable_ssl|ssl_key)\b',
    caseSensitive: false,
  );
  static final RegExp _pinningSetup = RegExp(
    r'badCertificateCallback|validateCertificate|SecurityContext|'
    r'IOHttpClientAdapter|certificatePinning',
    caseSensitive: false,
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    if (shouldSkipRuleImplementationFile(filePath)) {
      return const <Vulnerability>[];
    }
    if (!_remoteSslGate.hasMatch(content) || !_pinningSetup.hasMatch(content)) {
      return const <Vulnerability>[];
    }
    final List<String> lines = stripComments(content.split('\n'));
    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (!_remoteSslGate.hasMatch(line)) {
        continue;
      }
      final int windowEnd = (i + 25).clamp(0, lines.length);
      final String window = lines.sublist(i, windowEnd).join('\n');
      if (_pinningSetup.hasMatch(window)) {
        return <Vulnerability>[
          Vulnerability(
            ruleId: 'DART-002e',
            title: 'TLS pinning gated by remote configuration',
            description:
                'Certificate pinning or validation is only applied when a '
                'remote flag (e.g. enableSSL) is true. An attacker who disables '
                'the flag via Remote Config can strip pinning for all users.',
            recommendation:
                'Enable pinning unconditionally in production builds; use remote '
                'config only for non-security telemetry.',
            filePath: filePath,
            category: category,
            severity: Severity.medium,
            confidence: FindingConfidence.medium,
            lineNumber: i + 1,
            snippet: line.trim(),
            cwe: 'CWE-295',
            owasp: _owasp,
          ),
        ];
      }
    }
    return const <Vulnerability>[];
  }
}
