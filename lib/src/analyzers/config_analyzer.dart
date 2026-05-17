// lib/src/analyzers/config_analyzer.dart

import 'dart:io';

import 'package:path/path.dart' as p;

import '../models/severity.dart';
import '../models/vulnerability.dart';

/// Project config: `.gitignore`, Gradle signing, ProGuard rules.
class ConfigAnalyzer {
  static const String _category = 'Secret Management';

  static final RegExp _releaseDebugKeystore = RegExp(
    r'release\s*\{[\s\S]{0,1200}?(?:debug\.keystore|'
    r'\.android[/\\]debug\.keystore|signingConfigs\.debug)',
    caseSensitive: false,
  );
  static final RegExp _storeFileDebug = RegExp(
    r'storeFile\s+.*?debug\.keystore',
    caseSensitive: false,
    dotAll: true,
  );
  static final RegExp _proguardKeepWildcard = RegExp(
    r'-keep\s+class\s+[\w$.]+\.\*\*\s*\{',
  );

  List<Vulnerability> analyze(String projectPath) {
    final List<Vulnerability> findings = <Vulnerability>[];
    findings.addAll(_checkEnvGitignore(projectPath));
    findings.addAll(_checkGradleSigning(projectPath));
    findings.addAll(_checkProguardRules(projectPath));
    return findings;
  }

  List<Vulnerability> _checkEnvGitignore(String projectPath) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final File gitignore = File(p.join(projectPath, '.gitignore'));
    if (!gitignore.existsSync()) {
      return findings;
    }
    final String gitignoreContent = gitignore.readAsStringSync();
    final List<String> envPaths = <String>[];
    for (final String candidate in <String>[
      'env/.env_prod',
      'env/.env_dev',
      '.env',
      '.env.prod',
    ]) {
      if (File(p.join(projectPath, candidate)).existsSync()) {
        envPaths.add(candidate);
      }
    }
    if (envPaths.isEmpty) {
      return findings;
    }
    final bool envIgnored = RegExp(
      r'(?:^|\n)\s*(?:env/|\.env)',
      multiLine: true,
    ).hasMatch(gitignoreContent);
    if (envIgnored) {
      return findings;
    }
    for (final String envPath in envPaths) {
      findings.add(Vulnerability(
        ruleId: 'CONFIG-001',
        title: 'Env file not covered by .gitignore',
        description:
            '$envPath exists in the repo but .gitignore does not appear to '
            'exclude env files. Secrets may be committed accidentally.',
        recommendation:
            'Add env/.env* and .env* to .gitignore; use CI secrets for production.',
        filePath: envPath,
        category: _category,
        severity: Severity.medium,
        cwe: 'CWE-798',
        owasp: 'M9: Insecure Data Storage',
      ));
    }
    return findings;
  }

  List<Vulnerability> _checkGradleSigning(String projectPath) {
    final List<Vulnerability> findings = <Vulnerability>[];
    for (final String relative in <String>[
      'android/app/build.gradle',
      'android/app/build.gradle.kts',
    ]) {
      final File file = File(p.join(projectPath, relative));
      if (!file.existsSync()) {
        continue;
      }
      final String content = file.readAsStringSync();
      if (!_releaseDebugKeystore.hasMatch(content) &&
          !_storeFileDebug.hasMatch(content)) {
        continue;
      }
      findings.add(Vulnerability(
        ruleId: 'CONFIG-003',
        title: 'Release build uses debug keystore',
        description:
            'The release signing configuration references the debug keystore '
            'or signingConfigs.debug. Release APKs/AABs would be signed with '
            'a publicly known key.',
        recommendation:
            'Configure a dedicated release keystore in signingConfigs.release '
            'and reference it only from the release buildType.',
        filePath: relative,
        category: 'Android Build',
        severity: Severity.critical,
        cwe: 'CWE-321',
        owasp: 'M9: Insecure Data Storage',
      ));
    }
    return findings;
  }

  List<Vulnerability> _checkProguardRules(String projectPath) {
    final List<Vulnerability> findings = <Vulnerability>[];
    final Directory androidDir = Directory(p.join(projectPath, 'android'));
    if (!androidDir.existsSync()) {
      return findings;
    }
    for (final FileSystemEntity entity in androidDir.listSync(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is! File) {
        continue;
      }
      final String name = p.basename(entity.path);
      if (!name.contains('proguard') || !name.endsWith('.pro')) {
        continue;
      }
      final String content = entity.readAsStringSync();
      if (!_proguardKeepWildcard.hasMatch(content)) {
        continue;
      }
      final String relative = p.relative(entity.path, from: projectPath);
      findings.add(Vulnerability(
        ruleId: 'CONFIG-004',
        title: 'ProGuard keep rule preserves entire package tree',
        description:
            'A -keep class …**.** rule retains all types under an app '
            'namespace, which largely defeats R8 shrinking and obfuscation.',
        recommendation:
            'Replace broad -keep rules with narrow @Keep annotations or '
            '-keep on specific entry points only.',
        filePath: relative,
        category: 'Android Build',
        severity: Severity.high,
        cwe: 'CWE-656',
        owasp: 'M7: Client Code Quality',
        lineNumber: _lineNumberOfPattern(content, _proguardKeepWildcard),
      ));
    }
    return findings;
  }

  static int? _lineNumberOfPattern(String content, RegExp pattern) {
    final RegExpMatch? match = pattern.firstMatch(content);
    if (match == null) {
      return null;
    }
    return content.substring(0, match.start).split('\n').length;
  }
}
