// lib/src/rules/dart/flutter_secure_storage_encryption_rule.dart

import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-018` — [AndroidOptions] with Keystore encryption explicitly off.
class FlutterSecureStorageEncryptionRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-018';

  @override
  String get title => 'FlutterSecureStorage encryption disabled on Android';

  @override
  String get category => 'Insecure Storage';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  static final RegExp _androidOptions = RegExp(r'\bAndroidOptions\s*\(');

  /// Named argument must be the literal `false` (not a variable).
  static final RegExp _encryptionDisabled = RegExp(
    r'encryptedSharedPreferences\s*:\s*false\b',
  );

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    if (!_androidOptions.hasMatch(content)) {
      return const <Vulnerability>[];
    }

    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));
    final Set<int> reportedLines = <int>{};

    for (int i = 0; i < lines.length; i++) {
      if (!_androidOptions.hasMatch(lines[i])) {
        continue;
      }
      final int end = (i + 14).clamp(0, lines.length);
      final String window = lines.sublist(i, end).join('\n');
      if (!_encryptionDisabled.hasMatch(window)) {
        continue;
      }
      if (reportedLines.contains(i + 1)) {
        continue;
      }
      reportedLines.add(i + 1);
      findings.add(Vulnerability(
        ruleId: ruleId,
        title: title,
        description:
            'AndroidOptions(encryptedSharedPreferences: false) disables '
            'AES-256 Keystore-backed encryption and stores values in '
            'plaintext SharedPreferences on Android.',
        recommendation:
            'Remove encryptedSharedPreferences: false or set it to true. '
            'Use the default AndroidOptions so flutter_secure_storage uses '
            'EncryptedSharedPreferences.',
        filePath: filePath,
        category: category,
        severity: Severity.high,
        confidence: FindingConfidence.high,
        lineNumber: i + 1,
        snippet: lines[i].trim(),
        cwe: 'CWE-312',
        owasp: _owasp,
      ));
    }

    return findings;
  }
}
