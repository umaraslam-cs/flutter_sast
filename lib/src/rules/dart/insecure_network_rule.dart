// lib/src/rules/dart/insecure_network_rule.dart

import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-002` family — detect insecure network usage in Dart code.
class InsecureNetworkRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-002';

  @override
  String get title => 'Insecure network configuration';

  @override
  String get category => 'Network Security';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M3: Insecure Communication';

  static final RegExp _httpUrl =
      RegExp(r'''["']http://([A-Za-z0-9_\-\.:]+)''');
  static final RegExp _badCertCallback = RegExp(
    r'badCertificateCallback\s*[:=]\s*\(.*\)\s*(?:=>|\{)\s*(?:return\s+)?true',
  );
  static final RegExp _onBadCert = RegExp(
    r'onBadCertificate\s*[:=]\s*\(.*\)\s*(?:=>|\{)\s*(?:return\s+)?true',
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = content.split('\n');

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trimLeft().startsWith('//')) {
        continue;
      }
      final int lineNo = i + 1;

      for (final Match match in _httpUrl.allMatches(line)) {
        final String host = match.group(1) ?? '';
        if (_isLocalHost(host)) {
          continue;
        }
        findings.add(Vulnerability(
          ruleId: 'DART-002',
          title: 'Insecure HTTP URL',
          description:
              'A cleartext http:// URL is used for network communication. '
              'Traffic can be observed and tampered with on the wire.',
          recommendation:
              'Use https:// for every remote endpoint and configure '
              'certificate pinning where feasible.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-319',
          owasp: _owasp,
        ));
      }

      if (_badCertCallback.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-002b',
          title: 'Bad certificate callback accepts all certificates',
          description:
              'badCertificateCallback returns true unconditionally, which '
              'effectively disables TLS certificate validation and enables '
              'trivial man-in-the-middle attacks.',
          recommendation:
              'Remove the callback or validate the certificate (issuer, '
              'fingerprint, host) before returning true.',
          filePath: filePath,
          category: category,
          severity: Severity.critical,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-295',
          owasp: _owasp,
        ));
      }

      if (line.contains('HttpClient') &&
          line.contains('findProxy') &&
          line.contains('PROXY ')) {
        findings.add(Vulnerability(
          ruleId: 'DART-002c',
          title: 'Hardcoded HTTP proxy configured',
          description:
              'An HttpClient.findProxy implementation returns a hardcoded '
              'PROXY entry. Traffic can be routed through an attacker '
              'controlled host.',
          recommendation:
              'Read proxy configuration from a trusted source (environment '
              'or platform-provided settings) and validate it before use.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-441',
          owasp: _owasp,
        ));
      }

      if (_onBadCert.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-002d',
          title: 'Dio onBadCertificate accepts all certificates',
          description:
              'Dio onBadCertificate returns true unconditionally, disabling '
              'TLS certificate validation for every request.',
          recommendation:
              'Remove the callback or validate the certificate before '
              'returning true.',
          filePath: filePath,
          category: category,
          severity: Severity.critical,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-295',
          owasp: _owasp,
        ));
      }
    }

    return findings;
  }

  bool _isLocalHost(String host) {
    return host.startsWith('localhost') ||
        host.startsWith('127.0.0.1') ||
        host.startsWith('10.') ||
        host.startsWith('192.168.');
  }
}
