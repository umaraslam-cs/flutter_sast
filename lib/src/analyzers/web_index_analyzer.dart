// lib/src/analyzers/web_index_analyzer.dart

import '../models/severity.dart';
import '../models/vulnerability.dart';

/// `WEB-001` — Missing Content-Security-Policy in Flutter web `index.html`.
class WebIndexAnalyzer {
  static const String filePath = 'web/index.html';
  static const String _category = 'Web';

  List<Vulnerability> analyze(String content) {
    if (RegExp(
      r'Content-Security-Policy|content-security-policy',
      caseSensitive: false,
    ).hasMatch(content)) {
      return const <Vulnerability>[];
    }
    return <Vulnerability>[
      const Vulnerability(
        ruleId: 'WEB-001',
        title: 'Missing Content-Security-Policy',
        description:
            'web/index.html does not define a Content-Security-Policy meta tag '
            'or header reference. XSS in hosted web builds is harder to mitigate.',
        recommendation:
            'Add a CSP meta tag or configure CSP on your web host/CDN.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-1021',
        owasp: 'M7: Client Code Quality',
        scored: false,
      ),
    ];
  }
}
