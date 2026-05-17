// lib/src/rules/dart/credentials_in_exception_rule.dart

import '../../analysis/sensitive_keys.dart';
import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-014` — Tokens or passwords interpolated into thrown exceptions.
class CredentialsInExceptionRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-014';

  @override
  String get title => 'Sensitive data in exception message';

  @override
  String get category => 'Insecure Storage';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  static final RegExp _throwLine = RegExp(
    r'\bthrow\s+(?:\w+\.)?\w*Exception\b|'
    r'\bthrow\s+FormatException\b|'
    r'\bthrow\s+StateError\b',
    caseSensitive: false,
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty || shouldSkipLineForAnalysis(line)) {
        continue;
      }
      if (!_throwLine.hasMatch(line)) {
        continue;
      }
      if (!line.contains(r'$') &&
          !SensitiveKeys.interpolatedSensitive.hasMatch(line)) {
        continue;
      }
      if (!SensitiveKeys.interpolatedSensitive.hasMatch(line) &&
          !RegExp(
            r'''['"][^'"]*(?:token|password|secret|credential)[^'"]*\$''',
            caseSensitive: false,
          ).hasMatch(line)) {
        continue;
      }

      findings.add(Vulnerability(
        ruleId: ruleId,
        title: 'Credential interpolated into exception',
        description:
            'An exception message interpolates a token, password, or other '
            'secret. Crash reporters (Firebase Crashlytics, Sentry) may '
            'capture the string in breadcrumbs or event payloads.',
        recommendation:
            'Throw generic errors without secret values; log redacted '
            'details only in debug builds.',
        filePath: filePath,
        category: category,
        severity: Severity.high,
        confidence: FindingConfidence.high,
        lineNumber: i + 1,
        snippet: line.trim().length > 80
            ? '${line.trim().substring(0, 60)}...'
            : line.trim(),
        cwe: 'CWE-209',
        owasp: _owasp,
      ));
    }

    return findings;
  }
}
