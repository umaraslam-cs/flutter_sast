import 'dart:io';

import 'package:flutter_sast/src/analyzers/android_manifest_analyzer.dart';
import 'package:flutter_sast/src/analyzers/env_analyzer.dart';
import 'package:flutter_sast/src/rules/dart/code_security_rule.dart';
import 'package:flutter_sast/src/rules/dart/hardcoded_credentials_rule.dart';
import 'package:flutter_sast/src/rules/dart/hardcoded_secrets_rule.dart';
import 'package:flutter_sast/src/rules/dart/flutter_secure_storage_encryption_rule.dart';
import 'package:flutter_sast/src/rules/dart/insecure_network_rule.dart';
import 'package:flutter_sast/src/rules/dart/weak_crypto_rule.dart';
import 'package:test/test.dart';

void main() {
  final HardcodedSecretsRule secrets = HardcodedSecretsRule();
  final HardcodedCredentialsRule credentials = HardcodedCredentialsRule();
  final CodeSecurityRule codeSecurity = CodeSecurityRule();
  final InsecureNetworkRule network = InsecureNetworkRule();
  final WeakCryptoRule weakCrypto = WeakCryptoRule();
  final EnvAnalyzer env = EnvAnalyzer();

  String fixture(String name) =>
      File('test/fixtures/regression/$name').readAsStringSync();

  group('regression T01–T06', () {
    test('T01 locales.g.dart — 0 × DART-001', () {
      final code = fixture('locales_snippet.dart');
      expect(
        secrets.analyze('lib/generated/locales.g.dart', code),
        isEmpty,
      );
    });

    test('T02 storage key constant — 0 × DART-001 Bearer', () {
      final code = fixture('storage_keys_snippet.dart');
      expect(
        secrets.analyze('lib/services/storage_keys.dart', code),
        isEmpty,
      );
    });

    test('T03 hardcoded credentials — 1 × DART-006 Critical', () {
      final code = fixture('auth_credentials_snippet.dart');
      final findings = credentials.analyze(
        'lib/auth/credentials.dart',
        code,
      );
      expect(findings.length, 1);
      expect(findings.single.ruleId, 'DART-006');
      expect(findings.single.severity.name, 'critical');
    });

    test('T04 toString — 0 × DART-005b', () {
      final code = fixture('to_string_snippet.dart');
      expect(
        codeSecurity
            .analyze('lib/widgets/upload_notification.dart', code)
            .where((v) => v.ruleId == 'DART-005b'),
        isEmpty,
      );
    });

    test('T05 MD5 cache — 0 × DART-005b', () {
      final code = fixture('md5_cache_snippet.dart');
      expect(
        codeSecurity.analyze('lib/util/cache_paths.dart', code)
            .where((v) => v.ruleId == 'DART-005b'),
        isEmpty,
      );
    });

    test('T06 TLS pinning callback — 0 Critical DART-002b', () {
      final code = fixture('dio_pinning_snippet.dart');
      final findings = network
          .analyze('lib/network/http_client.dart', code)
          .where((v) => v.ruleId == 'DART-002b');
      expect(findings, isNotEmpty);
      expect(findings.first.severity.name, isNot('critical'));
    });
  });

  test('T07 env file — DART-007', () {
    final content = fixture('env_snippet.env');
    expect(
      env.analyze('env/.env_dev', content).any((v) => v.ruleId == 'DART-007'),
      isTrue,
    );
  });

  test('T08 manifest — AND-003, AND-010, no AND-004 on application', () {
    const String manifest = '''
<manifest>
  <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
  <application android:exported="true" android:usesCleartextTraffic="true">
    <activity android:exported="true" android:name=".SecretActivity" />
  </application>
</manifest>
''';
    final findings = AndroidManifestAnalyzer().analyze(manifest);
    expect(findings.any((v) => v.ruleId == 'AND-003'), isTrue);
    expect(findings.any((v) => v.ruleId == 'AND-010'), isTrue);
    expect(
      findings
          .where((v) => v.ruleId == 'AND-004')
          .any((v) => v.snippet?.contains('<application') ?? false),
      isFalse,
    );
  });

  test('T09 default AndroidOptions — 0 × DART-018', () {
    final code = fixture('secure_storage_snippet.dart');
    expect(
      FlutterSecureStorageEncryptionRule()
          .analyze('lib/services/secure_storage.dart', code),
      isEmpty,
    );
  });

  test('MD5 cache context — no DART-004', () {
    final code = fixture('md5_cache_snippet.dart');
    final md5Findings = weakCrypto
        .analyze('lib/util/cache_paths.dart', code)
        .where((v) => v.ruleId == 'DART-004');
    expect(md5Findings, isEmpty);
  });
}
