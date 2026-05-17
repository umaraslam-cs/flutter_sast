import 'package:flutter_sast/src/config/sast_config.dart';
import 'package:flutter_sast/src/models/severity.dart';
import 'package:flutter_sast/src/models/vulnerability.dart';
import 'package:flutter_sast/src/rules/base_rule.dart';
import 'package:test/test.dart';

void main() {
  group('ruleIdMatchesProfilePattern', () {
    test('matches prefix wildcard', () {
      expect(ruleIdMatchesProfilePattern('DART-004b', 'DART-*'), isTrue);
      expect(ruleIdMatchesProfilePattern('AND-003', 'DART-*'), isFalse);
    });

    test('matches exact id', () {
      expect(ruleIdMatchesProfilePattern('DEPS-002', 'DEPS-002'), isTrue);
    });
  });

  group('SastConfig.applyRuleConfig', () {
    test('overrides severity for sub-rules from base rule config', () {
      const SastConfig config = SastConfig(
        rules: <String, RuleConfig>{
          'DART-004': RuleConfig(severityOverride: 'info'),
        },
      );
      const Vulnerability finding = Vulnerability(
        ruleId: 'DART-004b',
        title: 't',
        description: 'd',
        recommendation: 'r',
        filePath: 'lib/a.dart',
        category: 'Cryptography',
        severity: Severity.high,
      );
      final Vulnerability updated = config.applyRuleConfig(finding);
      expect(updated.severity, Severity.info);
      expect(updated.scored, isFalse);
    });
  });

  group('SastConfig.matchesCustomProfile', () {
    test('filters by configured patterns', () {
      const SastConfig config = SastConfig(
        profileRulePatterns: <String, List<String>>{
          'custom': <String>['DART-*', 'CONFIG-*'],
        },
      );
      expect(config.matchesCustomProfile('custom', 'DART-012'), isTrue);
      expect(config.matchesCustomProfile('custom', 'AND-001'), isFalse);
    });

    test('allows all when pattern list is empty', () {
      const SastConfig config = SastConfig(
        profileRulePatterns: <String, List<String>>{
          'custom': <String>[],
        },
      );
      expect(config.matchesCustomProfile('custom', 'AND-001'), isTrue);
    });
  });

  group('Severity.tryParse', () {
    test('parses case-insensitive labels', () {
      expect(Severity.tryParse('CRITICAL'), Severity.critical);
      expect(Severity.tryParse('info'), Severity.info);
      expect(Severity.tryParse('nope'), isNull);
    });
  });
}
