// lib/src/rules/dart/insecure_storage_rule.dart

import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-003` family — detect sensitive data stored or logged in cleartext.
class InsecureStorageRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-003';

  @override
  String get title => 'Insecure local storage of sensitive data';

  @override
  String get category => 'Insecure Storage';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  static final RegExp _sensitiveKeyword = RegExp(
    r'password|token|secret|key|credential|auth|pin|ssn|credit.?card|cvv|session',
    caseSensitive: false,
  );

  static final RegExp _sharedPrefsWrite = RegExp(
    r'(?:SharedPreferences|prefs)\b.*\.(?:setString|setInt|setBool)\s*\(',
  );

  static final RegExp _getStorageWrite = RegExp(
    r'(?:GetStorage|box|_box)\s*(?:\(\s*\))?\.write\s*\(',
  );

  static final RegExp _hivePut = RegExp(r'Hive\.box[^\.]*\.put\s*\(');
  static final RegExp _genericHivePut = RegExp(r'\.put\s*\(');

  static final RegExp _logCall = RegExp(r'(?:print|debugPrint|log)\s*\(');

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = content.split('\n');
    final bool hasHiveEncryption =
        content.contains('HiveAesCipher') || content.contains('encryptionCipher');

    for (int i = 0; i < lines.length; i++) {
      final String line = lines[i];
      if (line.trimLeft().startsWith('//')) {
        continue;
      }
      final int lineNo = i + 1;
      final bool hasSensitive = _sensitiveKeyword.hasMatch(line);
      if (!hasSensitive) {
        continue;
      }

      if (_sharedPrefsWrite.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-003',
          title: 'SharedPreferences stores sensitive data in cleartext',
          description:
              'SharedPreferences stores values in an unencrypted XML / plist '
              'on device. Sensitive data such as passwords or tokens should '
              'never be persisted there.',
          recommendation:
              'Use flutter_secure_storage (Keystore / Keychain) for any '
              'sensitive value.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-312',
          owasp: _owasp,
        ));
      }

      if (_getStorageWrite.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-003b',
          title: 'GetStorage stores sensitive data in cleartext',
          description:
              'GetStorage persists data as plaintext JSON on disk. Sensitive '
              'values written this way are accessible to anyone with file '
              'system access.',
          recommendation:
              'Use flutter_secure_storage for sensitive values.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-312',
          owasp: _owasp,
        ));
      }

      final bool isHiveCall =
          _hivePut.hasMatch(line) || (line.contains('Hive.box') &&
              _genericHivePut.hasMatch(line));
      if (isHiveCall && !hasHiveEncryption) {
        findings.add(Vulnerability(
          ruleId: 'DART-003c',
          title: 'Hive box used without encryption',
          description:
              'Hive is being used to persist what looks like sensitive data '
              'but no HiveAesCipher / encryptionCipher is configured in this '
              'file. Hive data is stored as plaintext by default.',
          recommendation:
              'Open the box with `encryptionCipher: HiveAesCipher(key)` and '
              'store the key in flutter_secure_storage.',
          filePath: filePath,
          category: category,
          severity: Severity.high,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-312',
          owasp: _owasp,
        ));
      }

      if (_logCall.hasMatch(line)) {
        findings.add(Vulnerability(
          ruleId: 'DART-003d',
          title: 'Sensitive data written to log output',
          description:
              'Sensitive data appears to be passed to print / debugPrint / '
              'log. Logs are persisted by the OS and can leak credentials.',
          recommendation:
              'Redact sensitive fields before logging or remove the log '
              'entirely in production builds.',
          filePath: filePath,
          category: category,
          severity: Severity.medium,
          lineNumber: lineNo,
          snippet: line.trim(),
          cwe: 'CWE-532',
          owasp: _owasp,
        ));
      }
    }

    return findings;
  }
}
