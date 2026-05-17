// lib/src/rules/dart/code_security_rule.dart

import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-005` family — general code-level security smells.
class CodeSecurityRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-005';

  @override
  String get title => 'Code security issue';

  @override
  String get category => 'Code Security';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static final RegExp _sqlInjection = RegExp(
    r'''(?:rawQuery|rawDelete|rawUpdate|rawInsert|execSQL)\s*\(\s*["'].*\$\{?''',
  );

  static final RegExp _pathTraversal = RegExp(
    r'(?<![A-Za-z0-9_])File\([^)]*\$(?:\{[^}]+\}|[A-Za-z_]\w*)[^)]*\)',
  );

  static final RegExp _sensitiveKeyword = sharedSensitiveKeyword;

  // Split tokens so this rule file does not match itself when scanned.
  static const String _dartMirrors = 'dart:' 'mirrors';
  static const String _mirrorSystem = 'Mirror' 'System';
  static const String _jsModeUnrestricted =
      'Javascript' 'Mode.unrestricted';
  static const String _jsModeUnrestrictedAlt =
      'JavaScript' 'Mode.unrestricted';

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty || shouldSkipLineForAnalysis(line)) continue;
      final int lineNo = i + 1;

      if (_sqlInjection.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-005',
          title: 'Possible SQL injection via string interpolation',
          description:
              'A SQL query appears to be built by interpolating a Dart '
              'expression directly into a query string. This is a classic '
              'SQL injection sink.',
          recommendation:
              'Use parameterized queries: pass values as bound parameters '
              'instead of interpolating into the SQL text.',
          filePath: filePath,
          category: category,
          severity: Severity.critical,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-89',
          owasp: 'M4: Insecure Authentication / Authorization',
        ));
      }

      if (_pathTraversal.hasMatch(line) && !line.contains('.join(')) {
        findings.add(Vulnerability(
          ruleId: 'DART-005b',
          title: 'Potential path traversal',
          description:
              'A File path is built from an interpolated expression without '
              'going through a path-join helper. Attacker-controlled segments '
              'can escape the intended directory via ".." sequences.',
          recommendation:
              'Use package:path `p.join` and canonicalize / validate the '
              'resulting path before reading or writing.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-22',
          owasp: 'M1: Improper Platform Usage',
        ));
      }

      if (line.contains(_dartMirrors) || line.contains(_mirrorSystem)) {
        findings.add(Vulnerability(
          ruleId: 'DART-005c',
          title: 'Use of dart:' 'mirrors',
          description:
              'The dart:' 'mirrors library enables broad runtime reflection '
              'which can be abused to bypass intended encapsulation or invoke '
              'unintended code paths.',
          recommendation:
              'Avoid the mirrors library in production code. Prefer code '
              'generation or explicit dispatch.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-470',
          owasp: 'M7: Client Code Quality',
        ));
      }

      if (line.contains(_jsModeUnrestricted) ||
          line.contains(_jsModeUnrestrictedAlt)) {
        findings.add(Vulnerability(
          ruleId: 'DART-005d',
          title: 'Unrestricted JavaScript mode in WebView',
          description:
              'The WebView is configured with unrestricted JavaScript. '
              'Loaded content can execute arbitrary scripts which may '
              'attack the host app via JS bridges.',
          recommendation:
              'Disable JavaScript when not required, or restrict the loaded '
              'origins and sanitize bridged messages.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-79',
          owasp: 'M7: Client Code Quality',
        ));
      }

      if (line.contains('Clipboard.setData')) {
        final int winStart = (i - 3).clamp(0, lines.length);
        final int winEnd = (i + 5).clamp(0, lines.length);
        final String window = lines.sublist(winStart, winEnd).join('\n');
        if (_sensitiveKeyword.hasMatch(window)) {
          findings.add(Vulnerability(
            ruleId: 'DART-005e',
            title: 'Sensitive data copied to clipboard',
            description:
                'Sensitive data appears to be placed on the system clipboard. '
                'Other apps can read clipboard contents in the background.',
            recommendation:
                'Avoid placing secrets on the clipboard. If unavoidable, '
                'clear the clipboard after a short delay and warn the user.',
            filePath: filePath,
            category: category,
            severity: Severity.medium,
            lineNumber: lineNo,
            snippet: line.trim(),
            cwe: 'CWE-312',
            owasp: 'M9: Insecure Data Storage',
          ));
        }
      }

      if (line.contains('authenticateWithBiometrics') &&
          line.contains('useErrorDialogs: false')) {
        findings.add(Vulnerability(
          ruleId: 'DART-005f',
          title: 'Biometric authentication with useErrorDialogs disabled',
          description:
              'Biometric authentication is invoked with useErrorDialogs: '
              'false, which suppresses the OS-level error UI and may hide '
              'fallback and lockout states from the user.',
          recommendation:
              'Leave useErrorDialogs at its default or implement a complete '
              'error-handling UI that covers lockout, no-biometrics-enrolled '
              'and cancellation cases.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-287',
          owasp: 'M1: Improper Credential Usage',
        ));
      }
    }

    return findings;
  }
}
