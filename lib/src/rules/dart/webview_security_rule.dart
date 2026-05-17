// lib/src/rules/dart/webview_security_rule.dart

import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-010` — WebView loads URL without apparent host allowlist (CWE-601).
class WebViewSecurityRule extends FilePatternRule {
  WebViewSecurityRule({this.allowedHosts = const <String>[]});

  final List<String> allowedHosts;

  @override
  String get ruleId => 'DART-010';

  @override
  String get title => 'WebView URL load without allowlist';

  @override
  String get category => 'Code Security';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static final RegExp _loadRequest = RegExp(
    r'\.(?:loadRequest|loadUrl)\s*\(',
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    if (!_loadRequest.hasMatch(content)) {
      return const <Vulnerability>[];
    }
    final bool hasAllowlist = RegExp(
      r'(?:allowedHosts|allowlist|whitelist|isAllowedHost|host\s*==|'
      r'webview_allowed|startsWith\s*\(\s*["\x27]https?://)',
      caseSensitive: false,
    ).hasMatch(content);
    if (hasAllowlist || allowedHosts.isNotEmpty) {
      return const <Vulnerability>[];
    }

    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (!_loadRequest.hasMatch(line)) {
        continue;
      }
      if (RegExp(
        r'loadRequest\s*\(\s*Uri\.parse\s*\(\s*["\x27]',
      ).hasMatch(line)) {
        continue;
      }
      findings.add(Vulnerability(
        ruleId: ruleId,
        title: 'WebView loads dynamic URL without host allowlist',
        description:
            'loadRequest/loadUrl is called with a non-literal URI and no '
            'allowlist helper was found in this file.',
        recommendation:
            'Validate host against an allowlist before loading; configure '
            'webview_allowed_hosts in .flutter_sast.yml for known domains.',
        filePath: filePath,
        category: category,
        severity: Severity.high,
        confidence: FindingConfidence.medium,
        lineNumber: i + 1,
        snippet: line.trim(),
        cwe: 'CWE-601',
        owasp: 'M7: Client Code Quality',
      ));
      break;
    }

    return findings;
  }
}
