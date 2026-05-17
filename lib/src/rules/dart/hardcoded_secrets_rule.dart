// lib/src/rules/dart/hardcoded_secrets_rule.dart

import '../../analysis/line_context.dart';
import '../../analysis/secret_heuristics.dart';
import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

class _SecretPattern {
  final String name;
  final RegExp regex;
  final Severity severity;
  final FindingConfidence confidence;
  final String cwe;

  const _SecretPattern({
    required this.name,
    required this.regex,
    required this.severity,
    required this.confidence,
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
        r'''(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["'](?!AIza)([A-Za-z0-9_\-]{16,})["']''',
        caseSensitive: false,
      ),
      severity: Severity.critical,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'AWS Access Key ID',
      regex: RegExp(r'AKIA[0-9A-Z]{16}'),
      severity: Severity.critical,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'AWS Secret Key',
      regex: RegExp(
        r'''aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*["']([A-Za-z0-9/+=]{40})["']''',
        caseSensitive: false,
      ),
      severity: Severity.critical,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Firebase API Key',
      regex: RegExp(r'AIza[0-9A-Za-z\-_]{35}'),
      severity: Severity.info,
      confidence: FindingConfidence.low,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Attribution SDK dev key',
      regex: RegExp(
        r'''(?:appsFlyerDevKey|af[_-]?dev[_-]?key|appsflyer[_-]?dev[_-]?key)\s*[=:]\s*["']([^"']{8,})["']''',
        caseSensitive: false,
      ),
      severity: Severity.medium,
      confidence: FindingConfidence.low,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Subscription SDK public key',
      regex: RegExp(r'(?:goog_|appl_)[A-Za-z0-9]{10,}'),
      severity: Severity.info,
      confidence: FindingConfidence.low,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Google OAuth Client ID',
      regex: RegExp(
          r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
      severity: Severity.info,
      confidence: FindingConfidence.low,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Private Key Block',
      regex: RegExp(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY'),
      severity: Severity.critical,
      confidence: FindingConfidence.high,
      cwe: 'CWE-321',
    ),
    _SecretPattern(
      name: 'Hardcoded Password',
      regex: RegExp(
        r'''(?<![A-Za-z0-9_])(?:password|passwd|pwd)\s*[=:]\s*["'](?!.*\$\{)([^"']{6,})["']''',
        caseSensitive: false,
      ),
      severity: Severity.high,
      confidence: FindingConfidence.high,
      cwe: 'CWE-259',
    ),
    _SecretPattern(
      name: 'Bearer Token',
      regex: RegExp(
        r'''(?:bearer\s+|Bearer\s+)([A-Za-z0-9\-_\.]{20,})|'''
        r'''(?:auth[_-]?token)\s*[=:]\s*["'](eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']''',
        caseSensitive: false,
      ),
      severity: Severity.high,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Stripe Secret Key',
      regex: RegExp(r'sk_live_[0-9a-zA-Z]{24,}'),
      severity: Severity.critical,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Twilio Account SID',
      regex: RegExp(
        r'''(?:account[_-]?sid|twilio[_-]?(?:account[_-]?)?sid)\s*[=:]\s*["'](AC[a-zA-Z0-9]{32})["']''',
        caseSensitive: false,
      ),
      severity: Severity.high,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'SendGrid API Key',
      regex: RegExp(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
      severity: Severity.high,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'Slack Token',
      regex: RegExp(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}'),
      severity: Severity.high,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
    _SecretPattern(
      name: 'GitHub Token',
      regex: RegExp(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'),
      severity: Severity.critical,
      confidence: FindingConfidence.high,
      cwe: 'CWE-798',
    ),
  ];

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    if (SecretHeuristics.isGeneratedDartPath(filePath)) {
      return const <Vulnerability>[];
    }
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty || shouldSkipLineForAnalysis(line)) continue;
      if (SecretHeuristics.isLocaleI18nConstantLine(line)) continue;
      if (SecretHeuristics.isStorageKeyDefinitionLine(line)) continue;

      final LineContextKind kind = LineContext.classify(line);
      if (kind == LineContextKind.testMock) continue;
      if (kind == LineContextKind.uiString) continue;

      for (final _SecretPattern pattern in _patterns) {
        final Match? match = pattern.regex.firstMatch(line);
        if (match == null) {
          continue;
        }
        if (_isPlaceholderMatch(pattern, match)) {
          continue;
        }
        if (_shouldSkipPattern(pattern, filePath, line, match)) {
          continue;
        }

        findings.add(Vulnerability(
          ruleId: ruleId,
          title: '${pattern.name} hardcoded in source',
          description: _descriptionFor(pattern),
          recommendation: _recommendationFor(pattern),
          filePath: filePath,
          category: category,
          severity: pattern.severity,
          confidence: pattern.confidence,
          lineNumber: i + 1,
          snippet: _redactSnippet(line, match),
          cwe: pattern.cwe,
          owasp: _owasp,
        ));
        break;
      }
    }

    return findings;
  }

  bool _isPlaceholderMatch(_SecretPattern pattern, Match match) {
    final String? captured =
        match.groupCount >= 1 ? match.group(1) : match.group(0);
    if (captured == null) {
      return false;
    }
    if (pattern.name == 'Generic API Key' ||
        pattern.name == 'Hardcoded Password' ||
        pattern.name == 'Bearer Token') {
      return LineContext.isPlaceholderSecretValue(captured);
    }
    return false;
  }

  bool _shouldSkipPattern(
    _SecretPattern pattern,
    String filePath,
    String line,
    Match match,
  ) {
    if (pattern.name == 'Hardcoded Password') {
      if (SecretHeuristics.isHardcodedCredentialAssignment(line)) {
        return true;
      }
      if (LineContext.isNavigationRouteConstantLine(line)) {
        return true;
      }
      final String? captured = match.groupCount >= 1 ? match.group(1) : null;
      if (captured != null) {
        if (LineContext.isRoutePathValue(captured)) {
          return true;
        }
        if (SecretHeuristics.isSnakeCaseIdentifierString(captured) &&
            !SecretHeuristics.looksLikeSecretValue(captured)) {
          return true;
        }
        if (!SecretHeuristics.looksLikeSecretValue(captured) &&
            !SecretHeuristics.hasHighEntropy(captured)) {
          return true;
        }
      }
    }
    if (pattern.name == 'Bearer Token') {
      final String? captured = match.groupCount >= 1 ? match.group(1) : null;
      if (captured != null &&
          SecretHeuristics.isSnakeCaseIdentifierString(captured)) {
        return true;
      }
    }
    if (pattern.name == 'Google OAuth Client ID') {
      if (filePath.endsWith('firebase_options.dart') ||
          LineContext.isFirebaseClientConfigLine(line)) {
        return true;
      }
    }
    return false;
  }

  String _descriptionFor(_SecretPattern pattern) {
    switch (pattern.name) {
      case 'Firebase API Key':
        return 'A Firebase client API key is present in source. These keys '
            'ship in mobile and web clients; restrict them in Google Cloud '
            '(API key restrictions, App Check) and enforce Firebase Security '
            'Rules—not by treating them like rotatable server passwords.';
      case 'Attribution SDK dev key':
        return 'A mobile attribution SDK development key (e.g. AppsFlyer) appears '
            'hardcoded. Restrict usage in the vendor dashboard and avoid treating it '
            'as a server secret.';
      case 'Subscription SDK public key':
        return 'A subscription SDK public store key (e.g. RevenueCat `goog_`/`appl_` '
            'prefixes) is hardcoded. Public store keys are expected in clients; enforce '
            'entitlements on your backend—never trust local prefs alone for authorization.';
      case 'Google OAuth Client ID':
        return 'A public OAuth client ID is present (designed to ship in mobile '
            'apps). Restrict with bundle IDs and redirect URIs in Google Cloud.';
      default:
        return 'A ${pattern.name} appears to be hardcoded in this file. '
            'Hardcoded credentials can be extracted from compiled binaries '
            'and leak to anyone with read access to the source.';
    }
  }

  String _recommendationFor(_SecretPattern pattern) {
    switch (pattern.name) {
      case 'Firebase API Key':
        return 'Enable App Check, tighten Firestore/Storage/Auth rules, and '
            'apply GCP API key restrictions for your app IDs and platforms.';
      case 'Attribution SDK dev key':
        return 'Confirm dashboard restrictions and remove dev keys from release '
            'builds if a separate production key is required.';
      case 'Subscription SDK public key':
        return 'Verify entitlements server-side; do not use local storage flags '
            'as the sole paywall gate.';
      case 'Google OAuth Client ID':
        return 'Confirm OAuth client restrictions in Google Cloud Console; '
            'use App Check and Firebase Auth rules for API access control.';
      default:
        return 'Move the secret to a secure runtime store (environment '
            'variable, encrypted secret manager, or a backend) and rotate '
            'this credential immediately.';
    }
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
