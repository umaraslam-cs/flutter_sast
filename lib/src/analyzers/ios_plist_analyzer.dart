// lib/src/analyzers/ios_plist_analyzer.dart

import '../models/severity.dart';
import '../models/vulnerability.dart';

/// Analyzes the iOS `Info.plist` for App Transport Security and privacy
/// disclosure issues.
class IosPlistAnalyzer {
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

    for (final String key in _privacyKeys) {
      if (content.contains('<key>$key</key>')) {
        findings.add(Vulnerability(
          ruleId: 'IOS-006',
          title: '$key declared in Info.plist',
          description:
              '$key is declared, meaning the app intends to access this '
              'sensitive resource. Verify the runtime use matches the user '
              'expectation set by the usage description string.',
          recommendation:
              'Audit usage at runtime and remove the key if the capability '
              'is no longer used.',
          filePath: filePath,
          category: _category,
          severity: Severity.info,
          cwe: 'CWE-359',
          owasp: 'M6: Inadequate Privacy Controls',
        ));
      }
    }

    return findings;
  }
}
