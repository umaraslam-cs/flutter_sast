// lib/src/rules/dart/dart_io_web_rule.dart

import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `WEB-002` — dart:io Platform usage without web guard (web profile).
class DartIoWebRule extends FilePatternRule {
  @override
  String get ruleId => 'WEB-002';

  @override
  String get title => 'dart:io used without web guard';

  @override
  String get category => 'Web';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    if (!content.contains("import 'dart:io'") &&
        !content.contains('import "dart:io"')) {
      return const <Vulnerability>[];
    }
    if (RegExp(r'kIsWeb|foundation\.kIsWeb').hasMatch(content)) {
      return const <Vulnerability>[];
    }
    final int lineNo = content
        .split('\n')
        .indexWhere((String l) => l.contains('dart:io'));
    return <Vulnerability>[
      Vulnerability(
        ruleId: ruleId,
        title: 'dart:io import without kIsWeb guard',
        description:
            'This file imports dart:io / uses Platform without a kIsWeb check. '
            'Flutter web builds will fail or behave inconsistently.',
        recommendation:
            'Use conditional imports or guard Platform calls with !kIsWeb.',
        filePath: filePath,
        category: category,
        severity: Severity.medium,
        lineNumber: lineNo >= 0 ? lineNo + 1 : null,
        snippet: "import 'dart:io'",
        cwe: 'CWE-693',
        owasp: 'M7: Client Code Quality',
        scored: false,
      ),
    ];
  }
}
