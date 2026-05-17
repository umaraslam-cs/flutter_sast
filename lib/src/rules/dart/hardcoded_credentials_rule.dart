// lib/src/rules/dart/hardcoded_credentials_rule.dart

import '../../analysis/secret_heuristics.dart';
import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-006` — High-precision hardcoded app credentials (CWE-798).
class HardcodedCredentialsRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-006';

  @override
  String get title => 'Hardcoded application credential';

  @override
  String get category => 'Secrets';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  static final RegExp _credentialAssign = RegExp(
    r"\b(?:String\s+)?(?:password|clientSecret|apiSecret|privateKey)\s*=\s*'([^']+)'",
    caseSensitive: false,
  );

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

      final RegExpMatch? match = _credentialAssign.firstMatch(line);
      if (match == null) {
        if (!SecretHeuristics.isHardcodedCredentialAssignment(line)) {
          continue;
        }
      } else {
        final String value = match.group(1)!;
        if (SecretHeuristics.isSnakeCaseIdentifierString(value) &&
            !SecretHeuristics.looksLikeSecretValue(value)) {
          continue;
        }
        if (!SecretHeuristics.looksLikeSecretValue(value) &&
            !SecretHeuristics.hasHighEntropy(value)) {
          continue;
        }
      }

      findings.add(Vulnerability(
        ruleId: ruleId,
        title: 'Hardcoded credential in application logic',
        description:
            'A password, client secret, or API secret is assigned from a string '
            'literal in non-generated Dart code. These values ship in the binary.',
        recommendation:
            'Load credentials from a secure backend, OS keystore, or build-time '
            'secrets injection — never hardcode in source.',
        filePath: filePath,
        category: category,
        severity: Severity.critical,
        confidence: FindingConfidence.high,
        lineNumber: i + 1,
        snippet: line.trim().length > 80
            ? '${line.trim().substring(0, 60)}...'
            : line.trim(),
        cwe: 'CWE-798',
        owasp: _owasp,
      ));
    }

    return findings;
  }
}
