// lib/src/rules/dart/sensitive_logging_rule.dart

import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-008` / `DART-009` — Auth headers and push/payment tokens in logs.
class SensitiveLoggingRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-008';

  @override
  String get title => 'Sensitive data in logs';

  @override
  String get category => 'Insecure Storage';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  static final RegExp _logInterceptorHeaders = RegExp(
    r'\b(?:LogInterceptor|PrettyDioLogger)\s*\([^)]*requestHeader\s*:\s*true',
    caseSensitive: false,
    dotAll: true,
  );
  static final RegExp _tokenLog = RegExp(
    r'(?:debugPrint|print)\s*\(\s*["\x27][^"\x27]*(?:FCM\s*TOKEN|getPayToken|APNS\s*TOKEN|payment\s*token)[^"\x27]*\$',
    caseSensitive: false,
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    if (shouldSkipRuleImplementationFile(filePath)) {
      return const <Vulnerability>[];
    }
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty || shouldSkipLineForAnalysis(line)) continue;
      final int lineNo = i + 1;

      if (_tokenLog.hasMatch(line) && line.contains(r'$')) {
        findings.add(Vulnerability(
          ruleId: 'DART-009',
          title: 'Push or payment token logged',
          description:
              'FCM, APNS, or payment token values appear in log output via '
              'string interpolation.',
          recommendation:
              'Remove token logging in production or wrap with kDebugMode.',
          filePath: filePath,
          category: category,
          severity: Severity.info,
          confidence: FindingConfidence.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-532',
          owasp: _owasp,
          scored: false,
        ));
      }
    }

    if (_logInterceptorHeaders.hasMatch(content)) {
      final int lineNo = content
          .substring(0, _logInterceptorHeaders.firstMatch(content)!.start)
          .split('\n')
          .length;
      findings.add(Vulnerability(
        ruleId: 'DART-008',
        title: 'HTTP request headers logged',
        description:
            'LogInterceptor is configured with requestHeader: true, which '
            'may log Authorization and other sensitive headers.',
        recommendation:
            'Disable requestHeader in release builds or redact Authorization.',
        filePath: filePath,
        category: category,
        severity: Severity.medium,
        confidence: FindingConfidence.high,
        lineNumber: lineNo,
        snippet: 'LogInterceptor(… requestHeader: true …)',
        cwe: 'CWE-532',
        owasp: _owasp,
      ));
    }

    return findings;
  }
}
