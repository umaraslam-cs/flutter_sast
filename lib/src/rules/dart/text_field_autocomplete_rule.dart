// lib/src/rules/dart/text_field_autocomplete_rule.dart

import '../../models/finding_confidence.dart';
import '../../models/severity.dart';
import '../../models/vulnerability.dart';
import '../base_rule.dart';

/// `DART-017` — Sensitive TextFields without IME autocomplete disabled.
class TextFieldAutocompleteRule extends FilePatternRule {
  @override
  String get ruleId => 'DART-017';

  @override
  String get title => 'Autocomplete enabled on sensitive TextField';

  @override
  String get category => 'Insecure Storage';

  @override
  List<String> get applicableExtensions => const <String>['.dart'];

  static const String _owasp = 'M9: Insecure Data Storage';

  static final RegExp _textField = RegExp(
    r'\b(?:TextField|TextFormField)\s*\(',
  );
  static final RegExp _sensitiveField = RegExp(
    r'obscureText\s*:\s*true|'
    r'TextInputType\.visiblePassword|'
    r'AutofillHints\.(?:password|newPassword|oneTimeCode)|'
    r'(?:hintText|labelText|label)\s*:\s*[^,)]*(?:password|passwd|pin|otp)',
    caseSensitive: false,
  );
  static final RegExp _enableSuggestionsOff =
      RegExp(r'enableSuggestions\s*:\s*false');
  static final RegExp _autocorrectOff = RegExp(r'autocorrect\s*:\s*false');

  @override
  List<Vulnerability> analyze(String filePath, String content) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final List<String> lines = stripComments(content.split('\n'));

    for (int i = 0; i < lines.length; i++) {
      if (!_textField.hasMatch(lines[i])) {
        continue;
      }
      final int end = (i + 22).clamp(0, lines.length);
      final String window = lines.sublist(i, end).join('\n');
      if (!_sensitiveField.hasMatch(window)) {
        continue;
      }
      if (_enableSuggestionsOff.hasMatch(window) &&
          _autocorrectOff.hasMatch(window)) {
        continue;
      }
      findings.add(Vulnerability(
        ruleId: ruleId,
        title: 'Sensitive TextField missing IME hardening',
        description:
            'A password, PIN, or OTP field does not set both '
            'enableSuggestions: false and autocorrect: false. Android may '
            'cache input in the IME suggestion database.',
        recommendation:
            'Set enableSuggestions: false and autocorrect: false on every '
            'sensitive TextField / TextFormField.',
        filePath: filePath,
        category: category,
        severity: Severity.medium,
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
