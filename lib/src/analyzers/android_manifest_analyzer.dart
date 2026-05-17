// lib/src/analyzers/android_manifest_analyzer.dart

import '../models/severity.dart';
import '../models/vulnerability.dart';

/// Analyzes the contents of `AndroidManifest.xml` for common Android
/// platform misconfigurations.
class AndroidManifestAnalyzer {
  AndroidManifestAnalyzer({this.exportedAllowlist = const <String>[]});

  final List<String> exportedAllowlist;

  static const String filePath = 'android/app/src/main/AndroidManifest.xml';
  static const String _category = 'Android Manifest';

  static final RegExp _debuggable = RegExp(r'android:debuggable\s*=\s*"true"');
  static final RegExp _allowBackup = RegExp(r'android:allowBackup\s*=\s*"true"');
  static final RegExp _cleartextTraffic =
      RegExp(r'android:usesCleartextTraffic\s*=\s*"true"');
  static final RegExp _exportedComponent = RegExp(
    r'<(activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*"true"[^>]*>',
    caseSensitive: false,
  );
  static final RegExp _manageExternalStorage = RegExp(
    r'android\.permission\.MANAGE_EXTERNAL_STORAGE',
  );
  static final RegExp _androidName = RegExp(r'android:name\s*=\s*"([^"]+)"');
  static final RegExp _externalStorage = RegExp(
    r'(?:READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE)',
  );
  static final RegExp _networkSecurityConfig =
      RegExp(r'android:networkSecurityConfig');
  static final RegExp _targetSdkVersion = RegExp(
    r'android:targetSdkVersion\s*=\s*"(\d+)"',
  );
  static final RegExp _mapsApiKey = RegExp(
    r'com\.google\.android\.geo\.API_KEY',
  );
  static final RegExp _googleApiKeyValue = RegExp(r'AIza[0-9A-Za-z\-_]{35}');
  static final RegExp _mediaExportComponent = RegExp(
    r'MediaBrowser|MediaButton|AudioService|just_audio',
    caseSensitive: false,
  );
  static final RegExp _exportedActivity = RegExp(
    r'<activity\b[^>]*android:exported\s*=\s*"true"[^>]*>',
    caseSensitive: false,
  );
  static final RegExp _launchModeTask = RegExp(
    r'android:launchMode\s*=\s*"(?:singleTask|singleInstance)"',
    caseSensitive: false,
  );
  static final RegExp _fullBackupContent =
      RegExp(r'android:fullBackupContent');
  static final RegExp _dataExtractionRules =
      RegExp(r'android:dataExtractionRules');

  List<Vulnerability> analyze(String content) {
    final List<Vulnerability> findings = <Vulnerability>[];

    if (_debuggable.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'AND-001',
        title: 'App is debuggable',
        description:
            'android:debuggable="true" allows attaching a debugger to the '
            'shipped application. Production builds must not be debuggable.',
        recommendation:
            'Remove android:debuggable from the manifest or set it to false. '
            'Flutter / Gradle handle this automatically for release builds.',
        filePath: filePath,
        category: _category,
        severity: Severity.critical,
        cwe: 'CWE-489',
        owasp: 'M7: Client Code Quality',
      ));
    }

    if (_allowBackup.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'AND-002',
        title: 'Auto-backup enabled',
        description:
            'android:allowBackup="true" lets adb / Google Drive back up the '
            'app sandbox, including any sensitive data stored there.',
        recommendation:
            'Set android:allowBackup="false" or provide a strict backup '
            'rules XML that excludes sensitive directories.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-312',
        owasp: 'M9: Insecure Data Storage',
      ));
      if (!_fullBackupContent.hasMatch(content) &&
          !_dataExtractionRules.hasMatch(content)) {
        findings.add(const Vulnerability(
          ruleId: 'AND-015',
          title: 'Backup enabled without exclusion rules',
          description:
              'allowBackup is true but neither android:fullBackupContent nor '
              'android:dataExtractionRules is declared. SharedPreferences, '
              'SQLite databases, and cache may sync to Google Drive '
              'unencrypted.',
          recommendation:
              'Add android:fullBackupContent / android:dataExtractionRules '
              'XML that excludes sensitive files, or set allowBackup="false".',
          filePath: filePath,
          category: _category,
          severity: Severity.high,
          cwe: 'CWE-312',
          owasp: 'M9: Insecure Data Storage',
        ));
      }
    }

    if (_cleartextTraffic.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'AND-003',
        title: 'Cleartext HTTP traffic permitted',
        description:
            'android:usesCleartextTraffic="true" allows the app to make '
            'plain HTTP requests, exposing traffic to interception.',
        recommendation:
            'Disable cleartext traffic or restrict it to specific debug '
            'hosts via a network_security_config XML file.',
        filePath: filePath,
        category: _category,
        severity: Severity.high,
        cwe: 'CWE-319',
        owasp: 'M3: Insecure Communication',
      ));
    }

    for (final RegExpMatch match in _exportedComponent.allMatches(content)) {
      final String tag = match.group(0) ?? '';
      if (!tag.contains('android:permission')) {
        // The main launcher activity must be exported without a permission;
        // flagging it would be a guaranteed false positive on every project.
        final int searchEnd = (match.end + 800).clamp(0, content.length);
        final String window = content.substring(match.start, searchEnd);
        if (window.contains('android.intent.action.MAIN')) continue;

        final String component = _androidName.firstMatch(tag)?.group(1) ?? tag;
        if (exportedAllowlist.any((String a) => component.contains(a))) {
          continue;
        }
        final bool mediaComponent = _mediaExportComponent.hasMatch(component);
        findings.add(Vulnerability(
          ruleId: 'AND-004',
          title: 'Exported component without permission',
          description: mediaComponent
              ? 'Component "$component" is exported without a permission. '
                  'This is common for background audio / media-browser integrations; '
                  'verify against your audio plugin docs before restricting export.'
              : 'Component "$component" is declared with android:exported="true" '
                  'but does not require an android:permission. Review whether '
                  'other apps should be able to invoke it.',
          recommendation: mediaComponent
              ? 'Follow your background media plugin documentation before restricting export. '
                  'Do not set exported="false" blindly if playback depends on it.'
              : 'Add an android:permission attribute or set android:exported '
                  'to false if the component is not meant to be invoked by '
                  'other apps.',
          filePath: filePath,
          category: _category,
          severity: mediaComponent ? Severity.low : Severity.medium,
          lineNumber: _lineNumberAt(content, match.start),
          snippet: _truncate(tag, 120),
          cwe: 'CWE-926',
          owasp: 'M2: Inadequate Supply Chain Security',
        ));
      }
    }

    if (_externalStorage.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'AND-005',
        title: 'External storage permission declared',
        description:
            'READ_EXTERNAL_STORAGE / WRITE_EXTERNAL_STORAGE expose files to '
            'every other app on the device.',
        recommendation:
            'Use scoped storage (MediaStore / SAF) and request only the '
            'specific media permissions you need on Android 13+.',
        filePath: filePath,
        category: _category,
        severity: Severity.low,
        cwe: 'CWE-312',
        owasp: 'M9: Insecure Data Storage',
      ));
    }

    if (_manageExternalStorage.hasMatch(content)) {
      findings.add(const Vulnerability(
        ruleId: 'AND-010',
        title: 'MANAGE_EXTERNAL_STORAGE permission declared',
        description:
            'MANAGE_EXTERNAL_STORAGE grants broad file access on Android 11+. '
            'Play Store requires a declared core use case.',
        recommendation:
            'Remove unless required; prefer scoped storage and SAF.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-250',
        owasp: 'M9: Insecure Data Storage',
      ));
    }

    for (final RegExpMatch match in _exportedActivity.allMatches(content)) {
      final String tag = match.group(0) ?? '';
      final int searchEnd = (match.end + 800).clamp(0, content.length);
      final String window = content.substring(match.start, searchEnd);
      if (!_launchModeTask.hasMatch(window)) {
        continue;
      }
      if (window.contains('android.intent.action.MAIN')) {
        continue;
      }
      final String component = _androidName.firstMatch(tag)?.group(1) ?? tag;
      findings.add(Vulnerability(
        ruleId: 'AND-014',
        title: 'Exported activity with task-hijacking launchMode',
        description:
            'Activity "$component" is exported and uses singleTask or '
            'singleInstance. Other apps may hijack the task stack (StrandHogg-style).',
        recommendation:
            'Use singleTop or standard for non-launcher activities; set '
            'android:exported="false" unless external launch is required.',
        filePath: filePath,
        category: _category,
        severity: Severity.high,
        lineNumber: _lineNumberAt(content, match.start),
        snippet: _truncate(tag, 120),
        cwe: 'CWE-926',
        owasp: 'M1: Improper Platform Usage',
      ));
    }

    if (_mapsApiKey.hasMatch(content) && _googleApiKeyValue.hasMatch(content)) {
      findings.add(Vulnerability(
        ruleId: 'AND-008',
        title: 'Maps platform API key in AndroidManifest',
        description:
            'A maps platform API key (AIza…) is embedded in the manifest. '
            'Restrict it in the cloud console (Android app restriction by '
            'package name + signing certificate).',
        recommendation:
            'Apply API key restrictions for this app ID; monitor usage quotas.',
        filePath: filePath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-798',
        owasp: 'M9: Insecure Data Storage',
      ));
    }

    if (!_networkSecurityConfig.hasMatch(content)) {
      final bool cleartextAllowed = _cleartextTraffic.hasMatch(content);
      final int? targetSdk = _parseTargetSdk(content);
      final bool legacyTarget = targetSdk != null && targetSdk < 28;
      if (cleartextAllowed || legacyTarget) {
        findings.add(Vulnerability(
          ruleId: 'AND-007',
          title: 'Missing networkSecurityConfig',
          description: cleartextAllowed
              ? 'Cleartext traffic is permitted but no '
                  'android:networkSecurityConfig is referenced. A network '
                  'security config can scope cleartext to specific debug hosts.'
              : 'targetSdkVersion is below 28 and no '
                  'android:networkSecurityConfig is referenced. Consider '
                  'restricting cleartext and trusted CAs explicitly.',
          recommendation:
              'Add a network_security_config XML and reference it via '
              'android:networkSecurityConfig in the <application> element.',
          filePath: filePath,
          category: _category,
          severity: Severity.low,
          cwe: 'CWE-319',
          owasp: 'M3: Insecure Communication',
        ));
      }
    }

    return findings;
  }

  static int? _parseTargetSdk(String content) {
    final RegExpMatch? m = _targetSdkVersion.firstMatch(content);
    if (m == null) {
      return null;
    }
    return int.tryParse(m.group(1)!);
  }

  static int _lineNumberAt(String content, int offset) =>
      content.substring(0, offset).split('\n').length;

  static String _truncate(String value, int maxLength) {
    if (value.length <= maxLength) {
      return value;
    }
    return '${value.substring(0, maxLength - 3)}...';
  }
}
