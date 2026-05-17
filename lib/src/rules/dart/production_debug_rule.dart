// lib/src/rules/dart/production_debug_rule.dart

import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-011` — HTTP/network inspector may be enabled outside prod guard.
class ProductionDebugRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-011';

  @override
  String get title => 'HTTP inspector enabled';

  @override
  String get category => 'Code Security';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static final RegExp _inspectorFlag = RegExp(
    r'\b(?:enableHttpInspector|enableApiInspector|enableNetworkInspector|'
    r'showNetworkInspector|showHttpInspector)\b',
    caseSensitive: false,
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    if (!_inspectorFlag.hasMatch(content)) {
      return const <Vulnerability>[];
    }
    final List<String> lines = stripComments(content.split('\n'));
    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (!_inspectorFlag.hasMatch(line)) {
        continue;
      }
      if (RegExp(
        r'Flavor\.prod|Flavor\.production|kReleaseMode|!=\s*Flavor\.prod',
        caseSensitive: false,
      ).hasMatch(line)) {
        continue;
      }
      if (RegExp(
        r'enable(?:Http|Api|Network)Inspector\s*=\s*true|'
        r'show(?:Http|Network)Inspector\s*=\s*true',
        caseSensitive: false,
      ).hasMatch(line)) {
        return <Vulnerability>[
          Vulnerability(
            ruleId: ruleId,
            title: 'HTTP inspector without production guard',
            description:
                'An HTTP or network inspector flag is enabled without an '
                'obvious production flavor guard.',
            recommendation:
                'Disable inspectors in release builds and block remote config '
                'from re-enabling them in production.',
            filePath: filePath,
            category: category,
            severity: Severity.medium,
            lineNumber: i + 1,
            snippet: line.trim(),
            cwe: 'CWE-489',
            owasp: 'M7: Client Code Quality',
          ),
        ];
      }
    }
    return const <Vulnerability>[];
  }
}
