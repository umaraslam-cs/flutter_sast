// lib/src/rules/base_rule.dart

import '../models/vulnerability.dart';

/// Sensitive-data keyword pattern shared across Dart rules.
///
/// Word-boundary anchors on short tokens (`\bkey\b`, `\bpin\b`) prevent
/// matches inside identifiers like `keyboardType` or `spinner`.
final RegExp sharedSensitiveKeyword = RegExp(
  r'password|passwd|pwd|token|secret|\bkey\b|credential|auth|'
  r'pin\b|ssn|credit.?card|cvv|session',
  caseSensitive: false,
);

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

  /// Returns [lines] with block comments (`/* */`) removed and single-line
  /// comment lines (`//`) blanked to empty strings.
  ///
  /// Line count is preserved (index i → result[i]) so that
  /// [Vulnerability.lineNumber] values remain correct after stripping.
  ///
  /// **Known limitation:** `/*` that appears inside a string literal
  /// (e.g. `RegExp(r'/\*/')`) is treated as a block-comment opener.
  /// A full Dart tokenizer would be needed to eliminate this edge case.
  List<String> stripComments(List<String> lines) {
    final List<String> result = <String>[];
    bool inBlock = false;
    for (String line in lines) {
      if (inBlock) {
        final int end = line.indexOf('*/');
        if (end < 0) {
          result.add('');
          continue;
        }
        inBlock = false;
        line = line.substring(end + 2);
      }
      // Strip inline /* ... */ that closes on the same line.
      final int blockOpen = line.indexOf('/*');
      if (blockOpen >= 0) {
        final int blockClose = line.indexOf('*/', blockOpen + 2);
        if (blockClose >= 0) {
          line = line.substring(0, blockOpen) + line.substring(blockClose + 2);
        } else {
          inBlock = true;
          line = line.substring(0, blockOpen);
        }
      }
      result.add(line.trimLeft().startsWith('//') ? '' : line);
    }
    return result;
  }
}
