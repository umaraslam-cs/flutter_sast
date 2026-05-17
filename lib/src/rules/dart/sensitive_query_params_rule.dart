// lib/src/rules/dart/sensitive_query_params_rule.dart

import '../../analysis/sensitive_keys.dart';
import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-012` — Credentials or tokens in URL query parameters.
class SensitiveQueryParamsRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-012';

  @override
  String get title => 'Sensitive data in URL query parameters';

  @override
  String get category => 'Network Security';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M3: Insecure Communication';

  static final RegExp _queryParameters = RegExp(
    r'queryParameters\s*:\s*\{',
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
      final int lineNo = i + 1;
      String? title;
      String? description;

      if (_queryParameters.hasMatch(line)) {
        final int end = (i + 8).clamp(0, lines.length);
        final String window = lines.sublist(i, end).join('\n');
        if (SensitiveKeys.queryParamKey.hasMatch(window)) {
          title = 'Sensitive queryParameters map entry';
          description =
              'A Uri queryParameters map includes a high-risk key (token, '
              'password, secret, etc.). Query strings are logged by proxies, '
              'CDNs, and server access logs.';
        }
      } else if (SensitiveKeys.urlQuerySensitive.hasMatch(line)) {
        title = 'Sensitive value in URL query string';
        description =
            'A URL literal or builder includes credentials in the query '
            'string (?token=, ?password=, etc.).';
      } else if (line.contains(r'$') &&
          SensitiveKeys.urlQuerySensitive.hasMatch(line)) {
        title = 'Interpolated sensitive query parameter';
        description =
            'A URL is built with interpolation into the query string using '
            'a sensitive parameter name.';
      } else if (line.contains('Uri.parse') &&
          line.contains('?') &&
          SensitiveKeys.interpolatedSensitive.hasMatch(line)) {
        title = 'Sensitive data interpolated into Uri';
        description =
            'Uri.parse builds a URL with interpolated sensitive values in '
            'the query or path.';
      }

      if (title == null) {
        continue;
      }

      findings.add(Vulnerability(
        ruleId: ruleId,
        title: title,
        description: description!,
        recommendation:
            'Pass secrets in Authorization headers or request bodies over '
            'HTTPS; never place them in query parameters.',
        filePath: filePath,
        category: category,
        severity: Severity.high,
        confidence: FindingConfidence.high,
        lineNumber: lineNo,
        snippet: line.trim().length > 80
            ? '${line.trim().substring(0, 60)}...'
            : line.trim(),
        cwe: 'CWE-598',
        owasp: _owasp,
      ));
    }

    return findings;
  }
}
