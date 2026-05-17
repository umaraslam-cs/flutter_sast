// lib/src/analyzers/config_analyzer.dart

import 'dart:io';

import 'package:path/path.dart' as p;

import '../models/severity.dart';
import '../models/vulnerability.dart';

/// `CONFIG-001` — `.env` files present but not gitignored.
class ConfigAnalyzer {
  static const String _category = 'Secret Management';

  List<Vulnerability> analyze(String projectPath) {
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
}
