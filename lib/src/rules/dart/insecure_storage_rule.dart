// lib/src/rules/dart/insecure_storage_rule.dart

import '../../analysis/line_context.dart';
import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-003` family — detect sensitive data stored or logged in cleartext.
class InsecureStorageRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-003';

  @override
  String get title => 'Insecure local storage of sensitive data';

  @override
  String get category => 'Insecure Storage';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  static final RegExp _getStorageWrite = RegExp(
    r'\bGetStorage\b\s*(?:\(\s*\))?\.write\s*\(',
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty || shouldSkipLineForAnalysis(line)) continue;
      final int lineNo = i + 1;

      if (LineContext.isSensitivePrefsWrite(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-003',
          title: 'SharedPreferences stores sensitive data in cleartext',
          description:
              'SharedPreferences stores values in an unencrypted XML / plist '
              'on device. High-risk keys (tokens, passwords, secrets) should '
              'not be persisted there.',
          recommendation:
              'Use flutter_secure_storage (Keystore / Keychain) for tokens '
              'and credentials.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          confidence: FindingConfidence.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-312',
          owasp: _owasp,
        ));
      }

      if (_getStorageWrite.hasMatch(line) &&
          LineContext.prefsHighRiskKey.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-003b',
          title: 'GetStorage stores sensitive data in cleartext',
          description:
              'GetStorage persists data as plaintext JSON on disk. Sensitive '
              'values written this way are accessible to anyone with file '
              'system access.',
          recommendation:
              'Use flutter_secure_storage for sensitive values.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          confidence: FindingConfidence.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-312',
          owasp: _owasp,
        ));
      }

      if (LineContext.logsSensitiveValue(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-003d',
          title: 'Sensitive data written to log output',
          description:
              'A credential value appears to be interpolated into print / '
              'debugPrint / log output. Logs can leak secrets to device logs.',
          recommendation:
              'Redact sensitive fields before logging or remove the log '
              'entirely in production builds.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          confidence: FindingConfidence.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-532',
          owasp: _owasp,
        ));
      }
    }

    return findings;
  }
}
