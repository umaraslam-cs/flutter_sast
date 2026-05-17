// test/rules_test.dart

import 'dart:io';

import 'package:test/test.dart';

import 'package:flutter_sast/flutter_sast.dart';
import 'package:flutter_sast/src/analyzers/pubspec_analyzer.dart';
import 'package:flutter_sast/src/rules/base_rule.dart';
import 'package:flutter_sast/src/analyzers/android_manifest_analyzer.dart';
import 'package:flutter_sast/src/rules/dart/code_security_rule.dart';
import 'package:flutter_sast/src/rules/dart/hardcoded_secrets_rule.dart';
import 'package:flutter_sast/src/rules/dart/insecure_network_rule.dart';
import 'package:flutter_sast/src/rules/dart/insecure_storage_rule.dart';
import 'package:flutter_sast/src/rules/dart/weak_crypto_rule.dart';

void main() {
  group('HardcodedSecretsRule', () {
    final HardcodedSecretsRule rule = HardcodedSecretsRule();

    test('detects Firebase API key as INFO with low confidence', () {
      const String code =
          "const firebaseValue = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q';";
      final List<Vulnerability> results =
          rule.analyze('lib/firebase.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.info);
      expect(results.first.confidence, FindingConfidence.low);
    });

    test('skips mock api key values', () {
      const String code = 'final apiKey = "test_key_1234567890";';
      final List<Vulnerability> results =
          rule.analyze('lib/mock.dart', code);
      expect(results, isEmpty);
    });

    test('detects subscription SDK public key pattern', () {
      const String code =
          'await Purchases.configure(PurchasesConfiguration("goog_abcdefghijklmnop"));';
      final List<Vulnerability> results =
          rule.analyze('lib/main.dart', code);
      expect(results.any((v) => v.title.contains('Subscription SDK')), isTrue);
    });

    test('detects hardcoded password field', () {
      const String code =
          "final user = User(password: 'sup3rs3cret123');";
      final List<Vulnerability> results =
          rule.analyze('lib/user.dart', code);
      expect(results, isNotEmpty);
    });

    test('does not flag navigation route named editPassword', () {
      const String code =
          "  static const String editPassword = '/edit-password';";
      final List<Vulnerability> results =
          rule.analyze('lib/common/routes.dart', code);
      expect(results, isEmpty);
    });

    test('skips Google OAuth client ID in firebase_options.dart', () {
      const String code = '''
    iosClientId:
        '832520175604-hkjs4gmd1tq3oq1cb8gie84csj6mk9sa.apps.googleusercontent.com',
''';
      final List<Vulnerability> results =
          rule.analyze('lib/firebase_options.dart', code);
      expect(results, isEmpty);
    });

    test('detects AWS access key as CRITICAL', () {
      const String code = "const awsKey = 'AKIAIOSFODNN7EXAMPLE';";
      final List<Vulnerability> results =
          rule.analyze('lib/aws.dart', code);
      expect(results, isNotEmpty);
      expect(results.first.severity, Severity.critical);
    });

    test('does not duplicate Firebase key as generic API key on same line', () {
      const String code =
          'apiKey: "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q";';
      final List<Vulnerability> results =
          rule.analyze('lib/backend/firebase/firebase_config.dart', code);
      expect(results.length, 1);
      expect(results.single.title, contains('Firebase'));
    });

    test('skips commented lines', () {
      const String code =
          "// const firebaseApiKey = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q';";
      final List<Vulnerability> results =
          rule.analyze('lib/commented.dart', code);
      expect(results, isEmpty);
    });

    test('does not flag RegExp definition lines in rule sources', () {
      const String line =
          "regex: RegExp(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY'),";
      final List<Vulnerability> results =
          rule.analyze('lib/src/rules/x.dart', line);
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

    test('ignores badCertificateCallback mentioned only in a comment', () {
      const String code = '''
// badCertificateCallback returns true unconditionally in docs
final x = 1;
''';
      final List<Vulnerability> results =
          rule.analyze('lib/tls.dart', code);
      expect(results.where((v) => v.ruleId == 'DART-002b'), isEmpty);
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

    test('does not flag SharedPreferences session counters', () {
      const String code = '''
await prefs.setInt(_keySessionCount, currentCount + 1);
await prefs.setString(_keyLastSessionDate, DateTime.now().toIso8601String());
''';
      final List<Vulnerability> results =
          rule.analyze('lib/app_review_service.dart', code);
      expect(results.where((v) => v.ruleId == 'DART-003'), isEmpty);
    });

    test('does not flag static log mentioning password without values', () {
      const String code =
          "print('Error: update password attempted with no logged in user!');";
      final List<Vulnerability> results =
          rule.analyze('lib/firebase_auth_manager.dart', code);
      expect(results.where((v) => v.ruleId == 'DART-003d'), isEmpty);
    });

    test('does not flag generic box.write without GetStorage', () {
      const String code = "await box.write('token', userToken);";
      final List<Vulnerability> results =
          rule.analyze('lib/cache.dart', code);
      expect(results.any((v) => v.ruleId == 'DART-003b'), isFalse);
    });
  });

  group('CodeSecurityRule', () {
    final CodeSecurityRule rule = CodeSecurityRule();

    test('does not flag upload model toString as path traversal', () {
      const String code = '''
  String toString() =>
      'UploadField(name: \$name, bytes: \${bytes?.length ?? 0}, height: \$height,)';
''';
      final List<Vulnerability> results =
          rule.analyze('lib/models/upload_field.dart', code);
      expect(results.where((v) => v.ruleId == 'DART-005b'), isEmpty);
    });

    test('does not flag temp dir + app constant log path', () {
      const String code =
          "final File logFile = File('\${tempDir.path}/\${K.logFilename}');";
      final List<Vulnerability> results =
          rule.analyze('lib/common/log/log_util.dart', code);
      expect(results.where((v) => v.ruleId == 'DART-005b'), isEmpty);
    });

    test('still flags user-controlled file name in File path', () {
      const String code =
          "final File f = File('\${baseDir.path}/\${userFileName}');";
      final List<Vulnerability> results =
          rule.analyze('lib/upload.dart', code);
      expect(results.where((v) => v.ruleId == 'DART-005b'), isNotEmpty);
    });
  });

  group('AndroidManifestAnalyzer', () {
    test('detects maps platform API key in manifest', () {
      const String manifest = '''
<meta-data android:name="com.google.android.geo.API_KEY"
    android:value="AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"/>
''';
      final findings = AndroidManifestAnalyzer().analyze(manifest);
      expect(findings.any((v) => v.ruleId == 'AND-008'), isTrue);
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

  group('PubspecAnalyzer', () {
    test('pinning advisory uses DEPS-003 not DEPS-002', () {
      const String pubspec = '''
dependencies:
  flutter:
    sdk: flutter
''';
      final findings = PubspecAnalyzer().analyze(pubspec);
      expect(
        findings.any((v) => v.ruleId == 'DEPS-003'),
        isTrue,
        reason: 'pinning advisory',
      );
      final deps002 = findings.where((v) => v.ruleId == 'DEPS-002').toList();
      expect(deps002.length, lessThanOrEqualTo(1));
    });
  });

  group('sharedSensitiveKeyword', () {
    test('does not match author', () {
      expect(sharedSensitiveKeyword.hasMatch('print(author.name)'), isFalse);
    });
  });

  group('ruleIdMatchesFilter', () {
    test('DEPS-0 does not match DEPS-001', () {
      expect(ruleIdMatchesFilter('DEPS-001', 'DEPS-0'), isFalse);
    });

    test('DART-002 matches DART-002b', () {
      expect(ruleIdMatchesFilter('DART-002b', 'DART-002'), isTrue);
    });

    test('DART-0020 filter does not match DART-002 finding', () {
      expect(ruleIdMatchesFilter('DART-002', 'DART-0020'), isFalse);
    });

    test('DART-002 does not match DART-003', () {
      expect(ruleIdMatchesFilter('DART-003', 'DART-002'), isFalse);
    });
  });

  group('self-scan', () {
    test('full package scan is clean for this CLI repo', () async {
      if (!File('pubspec.yaml').existsSync()) {
        return;
      }
      final ScanReport report = await FlutterSastScanner(
        options: const ScanOptions(
          includeAndroid: false,
          includeIos: false,
        ),
      ).scan('.');
      expect(report.vulnerabilities, isEmpty);
      expect(report.riskLevel, 'CLEAN');
      expect(report.securityScore, 100);
    });

    test('lib/src/rules/dart/ is not flagged when scanning this package', () async {
      if (!File('pubspec.yaml').existsSync()) {
        return;
      }
      final ScanReport report = await FlutterSastScanner(
        options: const ScanOptions(
          includeAndroid: false,
          includeIos: false,
        ),
      ).scan('.');
      final List<Vulnerability> ruleImplHits = report.vulnerabilities
          .where((Vulnerability v) => v.filePath.contains('lib/src/rules/dart/'))
          .toList();
      expect(
        ruleImplHits,
        isEmpty,
        reason: ruleImplHits.map((Vulnerability v) {
          return '${v.ruleId} ${v.filePath}:${v.lineNumber}';
        }).join(', '),
      );
    });
  });

  group('ScanReport', () {
    final DateTime now = DateTime(2025, 1, 1);

    ScanReport reportWith(List<Vulnerability> vulns) {
      return ScanReport(
        projectPath: '/tmp/project',
        projectName: 'test_project',
        scannedAt: now,
        vulnerabilities: vulns,
        filesScanned: 1,
        scanDuration: Duration.zero,
      );
    }

    test('securityScore == 100 when there are no findings', () {
      expect(reportWith(<Vulnerability>[]).securityScore, 100);
    });

    test('securityScore uses confidence-weighted deductions', () {
      final ScanReport r = reportWith(<Vulnerability>[
        const Vulnerability(
          ruleId: 'DART-001',
          title: 't',
          description: 'd',
          recommendation: 'r',
          filePath: 'f',
          category: 'c',
          severity: Severity.critical,
          confidence: FindingConfidence.high,
        ),
      ]);
      expect(r.securityScore, 75);
    });

    test('recommendations do not reduce securityScore', () {
      final ScanReport r = reportWith(<Vulnerability>[
        const Vulnerability(
          ruleId: 'DEPS-001',
          title: 't',
          description: 'd',
          recommendation: 'r',
          filePath: 'pubspec.yaml',
          category: 'Recommendation',
          severity: Severity.low,
          scored: false,
        ),
      ]);
      expect(r.securityScore, 100);
    });

    test('riskLevel == CLEAN with no findings', () {
      expect(reportWith(<Vulnerability>[]).riskLevel, 'CLEAN');
    });

    test('riskLevel == ADVISORY for DEPS-only findings', () {
      final ScanReport r = reportWith(<Vulnerability>[
        const Vulnerability(
          ruleId: 'DEPS-002',
          title: 't',
          description: 'd',
          recommendation: 'r',
          filePath: 'pubspec.yaml',
          category: 'Dependencies',
          severity: Severity.medium,
        ),
      ]);
      expect(r.riskLevel, 'ADVISORY');
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
