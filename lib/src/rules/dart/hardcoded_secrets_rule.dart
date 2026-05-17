// lib/src/rules/dart/hardcoded_secrets_rule.dart

import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

class _SecretPattern {
  final String name;
  final RegExp regex;
  final Severity severity;
  final String cwe;

  const _SecretPattern({
    required this.name,
    required this.regex,
    required this.severity,
    required this.cwe,
  });
}

/// `DART-001` — Detect a wide range of hardcoded secrets in Dart code.
class HardcodedSecretsRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-001';

  @override
  String get title => 'Hardcoded secret detected';

  @override
  String get category => 'Secrets';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  final List<_SecretPattern> _patterns = <_SecretPattern>[
    _SecretPattern(
      name: 'Generic API Key',
      regex: RegExp(
        r'''(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9_\-]{16,})["']''',
        caseSensitive: false,
      ),
      severity: Severity.critical,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'AWS Access Key ID',
      regex: RegExp(r'AKIA[0-9A-Z]{16}'),
      severity: Severity.critical,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'AWS Secret Key',
      regex: RegExp(
        r'''aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*["']([A-Za-z0-9/+=]{40})["']''',
        caseSensitive: false,
      ),
      severity: Severity.critical,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Firebase API Key',
      regex: RegExp(r'AIza[0-9A-Za-z\-_]{35}'),
      severity: Severity.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Google OAuth Client ID',
      regex: RegExp(
          r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
      severity: Severity.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Private Key Block',
      regex: RegExp(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY'),
      severity: Severity.critical,
      cwe: 'CWE-321',
    ),
    _SecretPattern(
      name: 'Hardcoded Password',
      regex: RegExp(
        r'''(?:password|passwd|pwd)\s*[=:]\s*["'](?!.*\$\{)[^"']{6,}["']''',
        caseSensitive: false,
      ),
      severity: Severity.high,
      cwe: 'CWE-259',
    ),
    _SecretPattern(
      name: 'Bearer Token',
      regex: RegExp(
        r'''(?:bearer|token|auth[_-]?token)\s*[=:]\s*["']([A-Za-z0-9\-_\.]{20,})["']''',
        caseSensitive: false,
      ),
      severity: Severity.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Stripe Secret Key',
      regex: RegExp(r'sk_live_[0-9a-zA-Z]{24,}'),
      severity: Severity.critical,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Twilio Account SID',
      regex: RegExp(
        r'''(?:account[_-]?sid|twilio[_-]?(?:account[_-]?)?sid)\s*[=:]\s*["'](AC[a-zA-Z0-9]{32})["']''',
        caseSensitive: false,
      ),
      severity: Severity.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'SendGrid API Key',
      regex: RegExp(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
      severity: Severity.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Slack Token',
      regex: RegExp(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}'),
      severity: Severity.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'GitHub Token',
      regex: RegExp(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'),
      severity: Severity.critical,
      cwe: 'CWE-798',
    ),
  ];

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty) continue;

      for (final _SecretPattern pattern in _patterns) {
        final Match? match = pattern.regex.firstMatch(line);
        if (match == null) {
          continue;
        }

        findings.add(Vulnerability(
          ruleId: ruleId,
          title: '${pattern.name} hardcoded in source',
          description:
              'A ${pattern.name} appears to be hardcoded in this file. '
              'Hardcoded credentials can be extracted from compiled binaries '
              'and leak to anyone with read access to the source.',
          recommendation:
              'Move the secret to a secure runtime store (environment '
              'variable, encrypted secret manager, or a backend) and rotate '
              'this credential immediately.',
          filePath: filePath,
          category: category,
          severity: pattern.severity,
          lineNumber: i + 1,
          snippet: _redactSnippet(line, match),
          cwe: pattern.cwe,
          owasp: _owasp,
        ));
      }
    }

    return findings;
  }

  String _redactSnippet(String line, Match match) {
    final String original = match.group(0) ?? '';
    String redacted;
    if (original.length <= 4) {
      redacted = '*' * original.length;
    } else {
      redacted = '${original.substring(0, 4)}${'*' * (original.length - 4)}';
    }
    final String replaced = line.replaceFirst(original, redacted);
    if (replaced.length > 80) {
      return '${replaced.substring(0, 60)}... [REDACTED]';
    }
    return replaced;
  }
}
