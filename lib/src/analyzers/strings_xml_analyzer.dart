// lib/src/analyzers/strings_xml_analyzer.dart

import '../models/severity.dart';
import '../models/vulnerability.dart';

/// `AND-011` — Third-party SDK client tokens (e.g. Facebook) in `strings.xml`.
class StringsXmlAnalyzer {
  static const String _category = 'Android Resources';

  static final RegExp _clientTokenName = RegExp(
    r'<string\s+name="[^"]*client[_-]?token[^"]*"',
    caseSensitive: false,
  );
  static final RegExp _hexValue = RegExp(
    r'<string[^>]*>([a-fA-F0-9]{20,})</string>',
  );

  List<Vulnerability> analyze(String relativePath, String content) {
    if (!_clientTokenName.hasMatch(content)) {
      return const <Vulnerability>[];
    }
    final List<Vulnerability> findings = <Vulnerability>[];
    for (final RegExpMatch m in _hexValue.allMatches(content)) {
      final String token = m.group(1) ?? '';
      if (token.length < 20) {
        continue;
      }
      findings.add(Vulnerability(
        ruleId: 'AND-011',
        title: 'SDK client token in strings.xml',
        description:
            'A long hex client token is stored in $relativePath. Restrict usage '
            'in the vendor developer console.',
        recommendation:
            'Apply SDK token restrictions in the vendor console; rotate if leaked.',
        filePath: relativePath,
        category: _category,
        severity: Severity.medium,
        lineNumber: content.substring(0, m.start).split('\n').length,
        snippet: '<string …>[REDACTED]</string>',
        cwe: 'CWE-798',
        owasp: 'M9: Insecure Data Storage',
      ));
    }
    return findings;
  }
}
