// lib/src/rules/dart/weak_crypto_rule.dart

import '../../analysis/line_context.dart';
import '../../analysis/secret_heuristics.dart';
import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-004` family — flag weak cryptographic primitives and bad PRNG use.
class WeakCryptoRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-004';

  @override
  String get title => 'Weak cryptographic primitive';

  @override
  String get category => 'Cryptography';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M5: Insufficient Cryptography';

  // Split tokens so this rule file does not match itself when scanned.
  static final RegExp _md5 = RegExp(r'\bmd' r'5\b', caseSensitive: false);
  static final RegExp _sha1 =
      RegExp(r'\bsha' r'1\b|\bsha_1\b', caseSensitive: false);
  static const String _insecureRandom = 'Random' '()';
  static const String _ecbMode = 'EC' 'B';
  static final RegExp _hardcodedIv = RegExp(
    r'(?:iv|salt|nonce)\s*=\s*(?:Uint8List\.fromList\s*)?\[(?:\d+\s*,\s*){4,}',
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trim().isEmpty || shouldSkipLineForAnalysis(line)) continue;
      final int lineNo = i + 1;

      if (_md5.hasMatch(line)) {
        if (line.contains('flutter_sast:ignore md5-cache')) {
          continue;
        }
        final int windowStart = (i - 5).clamp(0, lines.length - 1);
        final int windowEnd = (i + 5).clamp(0, lines.length - 1);
        final List<String> window =
            lines.sublist(windowStart, windowEnd + 1);
        if (!SecretHeuristics.isSecurityCryptoContext(line, window)) {
          continue;
        }
        findings.add(Vulnerability(
          ruleId: 'DART-004',
          title: 'Use of MD' '5 hashing algorithm',
          description:
              'MD' '5 is cryptographically broken and unsuitable for security '
              'sensitive operations such as password hashing or signatures.',
          recommendation:
              'Use SHA-256 / SHA-512 for hashing or bcrypt / argon2 / scrypt '
              'for password storage.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          confidence: FindingConfidence.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-327',
          owasp: _owasp,
        ));
      }

      if (_sha1.hasMatch(line)) {
        final int windowStart = (i - 5).clamp(0, lines.length - 1);
        final int windowEnd = (i + 5).clamp(0, lines.length - 1);
        final List<String> window =
            lines.sublist(windowStart, windowEnd + 1);
        if (!SecretHeuristics.isSecurityCryptoContext(line, window)) {
          continue;
        }
        if (SecretHeuristics.isSha1BenignContext(line, window)) {
          continue;
        }
        findings.add(Vulnerability(
          ruleId: 'DART-004b',
          title: 'Use of SHA-' '1 hashing algorithm',
          description:
              'SHA-1 is considered weak and should not be used for any new '
              'security sensitive functionality.',
          recommendation:
              'Use SHA-256 or stronger for hashing.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-327',
          owasp: _owasp,
        ));
      }

      if (line.contains(_insecureRandom) &&
          !line.contains('Random.secure()')) {
        final int windowStart = (i - 5).clamp(0, lines.length - 1);
        final int windowEnd = (i + 5).clamp(0, lines.length - 1);
        final List<String> window =
            lines.sublist(windowStart, windowEnd + 1);
        if (LineContext.isSecurityRandomContext(line, window)) {
          findings.add(Vulnerability(
            ruleId: 'DART-004c',
            title: 'Use of insecure Random' '() for security material',
            description:
                'The non-secure Random constructor is not cryptographically '
                'secure. Using it to generate tokens, keys, IVs, salts, or OTP '
                'values produces predictable output.',
            recommendation:
                'Use Random.secure() from dart:math for any value that '
                'requires unpredictability.',
            filePath: filePath,
            category: category,
            severity: Severity.high,
            lineNumber: lineNo,
            snippet: line.trim(),
            cwe: 'CWE-338',
            owasp: _owasp,
          ));
        }
      }

      final bool mentionsEcb = line.contains(_ecbMode) ||
          (line.contains('AES') && line.contains('ec' 'b'));
      if (mentionsEcb) {
        findings.add(Vulnerability(
          ruleId: 'DART-004d',
          title: 'Use of AES in EC' 'B mode',
          description:
              'The EC' 'B block mode leaks structural information about the '
              'plaintext because identical blocks encrypt to identical '
              'ciphertext.',
          recommendation:
              'Use an authenticated mode (AES-GCM) or at minimum CBC with a '
              'random IV and a separate MAC.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-327',
          owasp: _owasp,
        ));
      }

      if (_hardcodedIv.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-004e',
          title: 'Hardcoded IV / salt / nonce',
          description:
              'An IV, salt, or nonce is initialized from a literal byte '
              'array. Reusing the same value across encryptions defeats the '
              'guarantees of modes like CBC and GCM.',
          recommendation:
              'Generate IV / salt / nonce values with Random.secure() for '
              'every encryption operation.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-329',
          owasp: _owasp,
        ));
      }
    }

    return findings;
  }
}
