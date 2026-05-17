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

  // Only the sqflite raw-SQL methods are unambiguously SQL sinks.
  // Generic names like `execute` and `query` match too many non-SQL APIs.
  static final RegExp _sqlInjection = RegExp(
    r'''(?:rawQuery|rawDelete|rawUpdate|rawInsert|execSQL)\s*\(\s*["'].*\$\{?''',
  );

  // Matches File(...) containing any Dart string interpolation ($var or ${expr}).
  // The exclusion check below skips calls that go through a path-join helper.
  static final RegExp _pathTraversal = RegExp(
    r'File\([^)]*\$(?:\{[^}]+\}|[A-Za-z_]\w*)[^)]*\)',
  );

  static final RegExp _sensitiveKeyword = sharedSensitiveKeyword;

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty) continue;
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

      if (_pathTraversal.hasMatch(line) &&
          !line.contains('.join(')) {
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

      if (line.contains('dart:mirrors') || line.contains('MirrorSystem')) {
        findings.add(Vulnerability(
          ruleId: 'DART-005c',
          title: 'Use of dart:mirrors',
          description:
              'dart:mirrors enables broad runtime reflection which can be '
              'abused to bypass intended encapsulation or invoke unintended '
              'code paths.',
          recommendation:
              'Avoid dart:mirrors in production code. Prefer code generation '
              'or explicit dispatch.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-470',
          owasp: 'M7: Client Code Quality',
        ));
      }

      if (line.contains('JavascriptMode.unrestricted') ||
          line.contains('JavaScriptMode.unrestricted')) {
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
