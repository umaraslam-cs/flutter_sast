// lib/src/analyzers/env_analyzer.dart

import '../models/finding_confidence.dart';
import '../models/severity.dart';
import '../models/vulnerability.dart';

/// `DART-007` — Plaintext encryption keys beside encrypted values in `.env` files.
class EnvAnalyzer {
  static const String _category = 'Secrets';

  static final RegExp _encryptionKey = RegExp(
    r'(?:^|\n)\s*([A-Z0-9_]*(?:ENCRYPTION_KEY|SECRET_KEY|MASTER_KEY))\s*=\s*"?([^"#\n]+)',
    multiLine: true,
  );

  static final RegExp _encryptedValue = RegExp(
    r'ENCRYPTED_',
    caseSensitive: false,
  );

  List<Vulnerability> analyze(String relativePath, String content) {
    if (!_encryptedValue.hasMatch(content)) {
      return const <Vulnerability>[];
    }
    final List<Vulnerability> findings = <Vulnerability>[];
    for (final RegExpMatch m in _encryptionKey.allMatches(content)) {
      final String name = m.group(1) ?? '';
      if (name.contains('ENCRYPTED_')) {
        continue;
      }
      final String value = (m.group(2) ?? '').trim();
      if (value.isEmpty || value.length < 8) {
        continue;
      }
      findings.add(Vulnerability(
        ruleId: 'DART-007',
        title: 'Plaintext encryption key in env file',
        description:
            'File "$relativePath" defines $name alongside ENCRYPTED_* values. '
            'The encryption key must not live in the same file as ciphertext.',
        recommendation:
            'Store the master key in CI secrets or platform keychain; ship only '
            'encrypted blobs in the repo.',
        filePath: relativePath,
        category: _category,
        severity: Severity.high,
        confidence: FindingConfidence.high,
        lineNumber: content.substring(0, m.start).split('\n').length,
        snippet: '$name = [REDACTED]',
        cwe: 'CWE-798',
        owasp: 'M9: Insecure Data Storage',
      ));
    }
    return findings;
  }
}
