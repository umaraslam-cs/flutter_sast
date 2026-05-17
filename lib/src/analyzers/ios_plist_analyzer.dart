// lib/src/analyzers/ios_plist_analyzer.dart

import '../models/severity.dart';
import '../models/vulnerability.dart';

/// Analyzes the iOS `Info.plist` for App Transport Security and privacy
/// disclosure issues.
class IosPlistAnalyzer {
  IosPlistAnalyzer({this.includePrivacyKeys = false});

  /// When false (default `security` profile), IOS-006 usage-description checks
  /// are omitted. When true (`privacy` profile), flags empty or generic strings.
  final bool includePrivacyKeys;

  static const String filePath = 'ios/Runner/Info.plist';
  static const String _category = 'iOS Info.plist';

  static final RegExp _allowsArbitraryLoads = RegExp(
    r'<key>NSAllowsArbitraryLoads</key>\s*<true/>',
    multiLine: true,
  );
  static final RegExp _allowsInsecureHttp = RegExp(
    r'<key>NSExceptionAllowsInsecureHTTPLoads</key>\s*<true/>',
    multiLine: true,
  );
  static final RegExp _allowsInWebContent = RegExp(
    r'<key>NSAllowsArbitraryLoadsInWebContent</key>',
  );
  static final RegExp _fileSharing = RegExp(
    r'<key>UIFileSharingEnabled</key>\s*<true/>',
    multiLine: true,
  );
  static final RegExp _documentsInPlace = RegExp(
    r'<key>LSSupportsOpeningDocumentsInPlace</key>\s*<true/>',
    multiLine: true,
  );

  static const List<String> _privacyKeys = <String>[
    'NSCameraUsageDescription',
    'NSMicrophoneUsageDescription',
    'NSLocationWhenInUseUsageDescription',
    'NSContactsUsageDescription',
    'NSPhotoLibraryUsageDescription',
  ];

  List<Vulnerability> analyze(String content) {
    final List<Vulnerability> findings = <Vulnerability>[];

    if (_allowsArbitraryLoads.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'IOS-001',
        title: 'NSAllowsArbitraryLoads is enabled',
        description:
            'NSAllowsArbitraryLoads bypasses App Transport Security and '
            'permits cleartext / weak-TLS connections to every host.',
        recommendation:
            'Remove NSAllowsArbitraryLoads or scope exceptions to specific '
            'hosts via NSExceptionDomains.',
        filePath: filePath,
        category: _category,
        severity: Severity.high,
        cwe: 'CWE-319',
        owasp: 'M3: Insecure Communication',
      ));
    }

    if (RegExp(
      r'<key>example\.com</key>[\s\S]*?NSExceptionAllowsInsecureHTTPLoads',
      multiLine: true,
    ).hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'IOS-003b',
        title: 'ATS exception for placeholder domain (dev template)',
        description:
            'Info.plist allows insecure HTTP for a placeholder exception domain — '
            'likely a leftover development template.',
        recommendation:
            'Remove development-only domains from NSExceptionDomains before release.',
        filePath: filePath,
        category: _category,
        severity: Severity.low,
        cwe: 'CWE-319',
        owasp: 'M3: Insecure Communication',
      ));
    }

    if (_allowsInsecureHttp.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'IOS-002',
        title: 'NSExceptionAllowsInsecureHTTPLoads is enabled',
        description:
            'NSExceptionAllowsInsecureHTTPLoads allows cleartext HTTP to a '
            'specific exception domain.',
        recommendation:
            'Remove the exception once the upstream supports HTTPS.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-319',
        owasp: 'M3: Insecure Communication',
      ));
    }

    if (_allowsInWebContent.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'IOS-003',
        title: 'NSAllowsArbitraryLoadsInWebContent is present',
        description:
            'NSAllowsArbitraryLoadsInWebContent disables ATS for WebView '
            'loads, allowing cleartext content rendered in-app.',
        recommendation:
            'Remove this key unless absolutely required and ensure WebView '
            'content is loaded over HTTPS.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-319',
        owasp: 'M3: Insecure Communication',
      ));
    }

    if (_fileSharing.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'IOS-004',
        title: 'UIFileSharingEnabled is true',
        description:
            'UIFileSharingEnabled exposes the app Documents directory to '
            'iTunes / Finder file sharing.',
        recommendation:
            'Disable file sharing or relocate sensitive files outside the '
            'Documents directory.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-312',
        owasp: 'M9: Insecure Data Storage',
      ));
    }

    if (_documentsInPlace.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'IOS-005',
        title: 'LSSupportsOpeningDocumentsInPlace is true',
        description:
            'LSSupportsOpeningDocumentsInPlace exposes the Documents '
            'directory to the Files app and other apps via document picker.',
        recommendation:
            'Disable in-place editing or move sensitive files to a private '
            'sub-container.',
        filePath: filePath,
        category: _category,
        severity: Severity.low,
        cwe: 'CWE-312',
        owasp: 'M9: Insecure Data Storage',
      ));
    }

    if (!includePrivacyKeys) {
      return findings;
    }

    for (final String key in _privacyKeys) {
      final RegExp keyBlock = RegExp(
        '<key>$key</key>\\s*<string>([^<]*)</string>',
        multiLine: true,
      );
      final RegExpMatch? match = keyBlock.firstMatch(content);
      if (match == null) {
        continue;
      }
      final String description = match.group(1) ?? '';
      if (!_isWeakUsageDescription(description)) {
        continue;
      }
      findings.add(Vulnerability(
        ruleId: 'IOS-006',
        title: 'Weak or missing $key string',
        description: description.trim().isEmpty
            ? '$key is present but the usage description string is empty. '
                'App Store review requires a clear explanation of why the '
                'permission is needed.'
            : '$key uses a generic or placeholder usage string that does '
                'not explain why access is needed.',
        recommendation:
            'Replace with a specific, user-facing explanation of how the '
            'app uses this capability.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-359',
        owasp: 'M6: Inadequate Privacy Controls',
      ));
    }

    return findings;
  }

  static bool _isWeakUsageDescription(String text) {
    final String t = text.trim();
    if (t.isEmpty) {
      return true;
    }
    if (t.length < 12) {
      return true;
    }
    if (RegExp(
      r'^(?:This app needs |Allow |We need |App requires |Needs access to )',
      caseSensitive: false,
    ).hasMatch(t)) {
      return true;
    }
    if (RegExp(
      r'^(?:camera|microphone|location|contacts|photo library) access\.?$',
      caseSensitive: false,
    ).hasMatch(t)) {
      return true;
    }
    return false;
  }
}
