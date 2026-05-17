import 'dart:io';

import 'package:flutter_sast/src/analyzers/android_manifest_analyzer.dart';
import 'package:flutter_sast/src/analyzers/ios_plist_analyzer.dart';
import 'package:flutter_sast/src/analyzers/pubspec_analyzer.dart';
import 'package:test/test.dart';

void main() {
  late String androidXml;
  late String iosPlist;

  setUpAll(() {
    androidXml = File('test/fixtures/android_manifest_sample.xml')
        .readAsStringSync();
    iosPlist =
        File('test/fixtures/ios_plist_sample.plist').readAsStringSync();
  });

  group('AndroidManifestAnalyzer fixtures', () {
    test('detects cleartext, backup, maps key, empty permission', () {
      final findings = AndroidManifestAnalyzer().analyze(androidXml);
      expect(findings.any((v) => v.ruleId == 'AND-003'), isTrue);
      expect(findings.any((v) => v.ruleId == 'AND-002'), isTrue);
      expect(findings.any((v) => v.ruleId == 'AND-008'), isTrue);
      expect(findings.any((v) => v.ruleId == 'AND-009'), isTrue);
    });

    test('skips launcher MAIN activity for AND-004', () {
      final findings = AndroidManifestAnalyzer().analyze(androidXml);
      final and004 = findings.where((v) => v.ruleId == 'AND-004').toList();
      expect(and004, isNotEmpty);
      expect(
        and004.any((v) => v.description.contains('MainActivity')),
        isFalse,
      );
      expect(
        and004.any((v) => v.description.contains('AudioService')),
        isTrue,
      );
    });
  });

  group('IosPlistAnalyzer fixtures', () {
    test('detects ATS bypass and camera usage key', () {
      final findings = IosPlistAnalyzer().analyze(iosPlist);
      expect(findings.any((v) => v.ruleId == 'IOS-001'), isTrue);
      expect(findings.any((v) => v.ruleId == 'IOS-006'), isTrue);
    });
  });

  group('PubspecAnalyzer CLI vs app', () {
    test('skips app-only advisories for pure Dart CLI pubspec', () {
      const String cliPubspec = '''
name: my_cli
dependencies:
  args: ^2.0.0
executables:
  my_cli: my_cli
''';
      final findings = PubspecAnalyzer().analyze(
        cliPubspec,
        includeAppDependencyAdvisories: false,
      );
      expect(findings.where((v) => v.ruleId == 'DEPS-002'), isEmpty);
      expect(findings.where((v) => v.ruleId == 'DEPS-003'), isEmpty);
    });
  });
}
