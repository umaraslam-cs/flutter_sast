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

  // Both patterns use dotAll so they match across newlines, catching:
  //   callback = (cert, host, port) => true;          // single-line
  //   callback = (cert, host, port) { return true; }  // multi-line
  static final RegExp _badCertPattern = RegExp(
    r'badCertificateCallback\s*[:=]\s*\([^)]*\)\s*'
    r'(?:=>\s*true|\{[^}]*?\breturn\s+true\b)',
    dotAll: true,
  );
  static final RegExp _onBadCertPattern = RegExp(
    r'onBadCertificate\s*[:=]\s*\([^)]*\)\s*'
    r'(?:=>\s*true|\{[^}]*?\breturn\s+true\b)',
    dotAll: true,
  );

  // Split tokens so this rule file does not match itself when scanned.
  static const String _findProxyLiteral = 'find' 'Proxy';
  static const String _proxyScheme = 'PROXY' ' ';
  static final RegExp _findProxyAssignment = RegExp(r'\.findProxy\s*[:=]');

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));
    final String stripped = lines.join('\n');

    // HTTP URL: best detected per-line for accurate line numbers.
    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty || shouldSkipLineForAnalysis(line)) continue;
      final int lineNo = i + 1;

      for (final Match match in _httpUrl.allMatches(line)) {
        final String host = match.group(1) ?? '';
        if (_isLocalHost(host)) continue;
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
    }

    // Cert validation and proxy: run on the stripped content so that
    // commented-out callbacks are not flagged, and multi-line patterns
    // (lambda body on the next line) are detected.
    _checkCertAndProxy(stripped, filePath, findings);

    return findings;
  }

  void _checkCertAndProxy(
    String stripped,
    String filePath,
    List<Vulnerability> out,
  ) {
    for (final RegExpMatch m in _badCertPattern.allMatches(stripped)) {
      final int lineNo = stripped.substring(0, m.start).split('\n').length;
      final String raw = m.group(0)!.replaceAll('\n', ' ').trim();
      out.add(Vulnerability(
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
        snippet: raw.length > 80 ? '${raw.substring(0, 80)}…' : raw,
        cwe: 'CWE-295',
        owasp: _owasp,
      ));
    }

    for (final RegExpMatch m in _onBadCertPattern.allMatches(stripped)) {
      final int lineNo = stripped.substring(0, m.start).split('\n').length;
      final String raw = m.group(0)!.replaceAll('\n', ' ').trim();
      out.add(Vulnerability(
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
        snippet: raw.length > 80 ? '${raw.substring(0, 80)}…' : raw,
        cwe: 'CWE-295',
        owasp: _owasp,
      ));
    }

    if (_findProxyAssignment.hasMatch(stripped) &&
        stripped.contains(_proxyScheme)) {
      final int idx = stripped.indexOf(_findProxyLiteral);
      final int lineNo = stripped.substring(0, idx).split('\n').length;
      out.add(Vulnerability(
        ruleId: 'DART-002c',
        title: 'Hardcoded HTTP proxy configured',
        description:
            'An HttpClient.' 'findProxy implementation returns a hardcoded '
            'PROXY ' 'entry. Traffic can be routed through an attacker '
            'controlled host.',
        recommendation:
            'Read proxy configuration from a trusted source (environment '
            'or platform-provided settings) and validate it before use.',
        filePath: filePath,
        category: category,
        severity: Severity.medium,
        lineNumber: lineNo,
        snippet: '$_findProxyLiteral … $_proxyScheme<host>',
        cwe: 'CWE-441',
        owasp: _owasp,
      ));
    }
  }

  bool _isLocalHost(String host) {
    // Strip port suffix before comparing.
    final String h = host.contains(':') ? host.split(':').first : host;
    if (h == 'localhost' || h == '127.0.0.1' || h == '::1') return true;
    // RFC-1918: 10.0.0.0/8
    if (RegExp(r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$').hasMatch(h)) return true;
    // RFC-1918: 172.16.0.0/12
    if (RegExp(r'^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$').hasMatch(h)) {
      return true;
    }
    // RFC-1918: 192.168.0.0/16
    if (RegExp(r'^192\.168\.\d{1,3}\.\d{1,3}$').hasMatch(h)) return true;
    return false;
  }
}
