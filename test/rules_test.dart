// test/rules_test.dart

import 'package:test/test.dart';

import 'package:flutter_sast/flutter_sast.dart';
import 'package:flutter_sast/src/rules/dart/hardcoded_secrets_rule.dart';
import 'package:flutter_sast/src/rules/dart/insecure_network_rule.dart';
import 'package:flutter_sast/src/rules/dart/insecure_storage_rule.dart';
import 'package:flutter_sast/src/rules/dart/weak_crypto_rule.dart';

void main() {
  group('HardcodedSecretsRule', () {
    final HardcodedSecretsRule rule = HardcodedSecretsRule();

    test('detects Firebase API key as HIGH', () {
      const String code =
          "const firebaseValue = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q';";
      final List<Vulnerability> results =
          rule.analyze('lib/firebase.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.high);
    });

    test('detects hardcoded password field', () {
      const String code =
          "final user = User(password: 'sup3rs3cret123');";
      final List<Vulnerability> results =
          rule.analyze('lib/user.dart', code);
      expect(results, isNotEmpty);
    });

    test('detects AWS access key as CRITICAL', () {
      const String code = "const awsKey = 'AKIAIOSFODNN7EXAMPLE';";
      final List<Vulnerability> results =
          rule.analyze('lib/aws.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.critical);
    });

    test('skips commented lines', () {
      const String code =
          "// const firebaseApiKey = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q';";
      final List<Vulnerability> results =
          rule.analyze('lib/commented.dart', code);
      expect(results, isEmpty);
    });
  });

  group('InsecureNetworkRule', () {
    final InsecureNetworkRule rule = InsecureNetworkRule();

    test('detects http://api.example.com as HIGH', () {
      const String code =
          "final response = await http.get(Uri.parse('http://api.example.com/v1'));";
      final List<Vulnerability> results =
          rule.analyze('lib/api.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.high);
    });

    test('allows http://localhost:3000', () {
      const String code =
          "final response = await http.get(Uri.parse('http://localhost:3000/v1'));";
      final List<Vulnerability> results =
          rule.analyze('lib/api.dart', code);
      expect(results, isEmpty);
    });

    test('detects badCertificateCallback returning true as CRITICAL', () {
      const String code =
          'client.badCertificateCallback = (cert, host, port) => true;';
      final List<Vulnerability> results =
          rule.analyze('lib/tls.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.critical);
    });
  });

  group('InsecureStorageRule', () {
    final InsecureStorageRule rule = InsecureStorageRule();

    test('detects prefs.setString password as HIGH', () {
      const String code =
          "await prefs.setString('password', userPassword);";
      final List<Vulnerability> results =
          rule.analyze('lib/storage.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.high);
    });

    test('detects print of token', () {
      const String code = "print('token: \$userToken');";
      final List<Vulnerability> results =
          rule.analyze('lib/logging.dart', code);
      expect(results, isNotEmpty);
    });
  });

  group('WeakCryptoRule', () {
    final WeakCryptoRule rule = WeakCryptoRule();

    test('detects md5.convert() as HIGH', () {
      const String code = 'final digest = md5.convert(utf8.encode(input));';
      final List<Vulnerability> results =
          rule.analyze('lib/hash.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.high);
    });

    test('detects sha1.convert()', () {
      const String code = 'final digest = sha1.convert(utf8.encode(input));';
      final List<Vulnerability> results =
          rule.analyze('lib/hash.dart', code);
      expect(results, isNotEmpty);
    });
  });

  group('ScanReport', () {
    final DateTime now = DateTime(2025, 1, 1);

    ScanReport reportWith(List<Vulnerability> vulns) {
      return ScanReport(
        projectPath: '/tmp/project',
        scannedAt: now,
        vulnerabilities: vulns,
        filesScanned: 1,
        scanDuration: Duration.zero,
      );
    }

    test('securityScore == 100 when there are no findings', () {
      expect(reportWith(<Vulnerability>[]).securityScore, 100);
    });

    test('securityScore < 100 with one CRITICAL finding', () {
      final ScanReport r = reportWith(<Vulnerability>[
        const Vulnerability(
          ruleId: 'DART-001',
          title: 't',
          description: 'd',
          recommendation: 'r',
          filePath: 'f',
          category: 'c',
          severity: Severity.critical,
        ),
      ]);
      expect(r.securityScore, lessThan(100));
    });

    test('riskLevel == CLEAN with no findings', () {
      expect(reportWith(<Vulnerability>[]).riskLevel, 'CLEAN');
    });

    test('riskLevel == CRITICAL with one CRITICAL finding', () {
      final ScanReport r = reportWith(<Vulnerability>[
        const Vulnerability(
          ruleId: 'DART-001',
          title: 't',
          description: 'd',
          recommendation: 'r',
          filePath: 'f',
          category: 'c',
          severity: Severity.critical,
        ),
      ]);
      expect(r.riskLevel, 'CRITICAL');
    });
  });
}
