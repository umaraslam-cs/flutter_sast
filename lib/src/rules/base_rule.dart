// lib/src/rules/base_rule.dart

import '../models/vulnerability.dart';

/// Base contract for every static analysis rule.
abstract class SastRule {
  String get ruleId;
  String get title;
  String get category;

  List<Vulnerability> analyze(String filePath, String content);
}

/// Rule that only fires on files with a matching extension.
abstract class FilePatternRule extends SastRule {
  List<String> get applicableExtensions;

  bool appliesTo(String filePath) {
    for (final String ext in applicableExtensions) {
      if (filePath.endsWith(ext)) {
        return true;
      }
    }
    return false;
  }
}
