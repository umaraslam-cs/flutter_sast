// lib/src/config/sast_config.dart

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

import '../models/severity.dart';
import '../models/vulnerability.dart';
import '../rules/base_rule.dart';

/// Project-level configuration loaded from `.flutter_sast.yml`.
class SastConfig {
  final List<String> excludeGlobs;
  final Map<String, RuleConfig> rules;
  final List<String> exportedAllowlist;
  final String profile;
  final List<String> webviewAllowedHosts;

  /// Rule ID patterns (`DART-*`, `AND-004`, …) for custom profile names only.
  final Map<String, List<String>> profileRulePatterns;

  const SastConfig({
    this.excludeGlobs = const <String>[
      '**/*.g.dart',
      '**/build/**',
      '**/.dart_tool/**',
    ],
    this.rules = const <String, RuleConfig>{},
    this.exportedAllowlist = const <String>[],
    this.profile = 'security',
    this.webviewAllowedHosts = const <String>[],
    this.profileRulePatterns = const <String, List<String>>{},
  });

  static const Set<String> builtInProfiles = <String>{
    'security',
    'privacy',
    'web',
  };

  static const String fileName = '.flutter_sast.yml';

  /// Loads config from [projectPath] if present; otherwise returns defaults.
  static Future<SastConfig> load(String projectPath) async {
    final File file = File(p.join(projectPath, fileName));
    if (!await file.exists()) {
      return const SastConfig();
    }
    try {
      final dynamic doc = loadYaml(await file.readAsString());
      if (doc is! YamlMap) {
        return const SastConfig();
      }
      return SastConfig._fromYaml(doc);
    } on YamlException {
      return const SastConfig();
    }
  }

  factory SastConfig._fromYaml(YamlMap doc) {
    final YamlMap? exclude = doc['exclude'] as YamlMap?;
    final List<String> globs = <String>[
      '**/*.g.dart',
      '**/build/**',
      '**/.dart_tool/**',
    ];
    final dynamic globNode = exclude?['glob'];
    if (globNode is YamlList) {
      for (final dynamic g in globNode) {
        if (g is String) {
          globs.add(g);
        }
      }
    }

    final Map<String, RuleConfig> ruleMap = <String, RuleConfig>{};
    final YamlMap? rulesNode = doc['rules'] as YamlMap?;
    if (rulesNode != null) {
      for (final dynamic key in rulesNode.keys) {
        if (key is! String) {
          continue;
        }
        final dynamic value = rulesNode[key];
        if (value is YamlMap) {
          ruleMap[key] = RuleConfig.fromYaml(value);
        }
      }
    }

    final List<String> allowlist = <String>[];
    final dynamic androidRules = doc['rules'];
    if (androidRules is YamlMap) {
      final dynamic and004 = androidRules['AND-004'];
      if (and004 is YamlMap) {
        final dynamic list = and004['exported_allowlist'];
        if (list is YamlList) {
          for (final dynamic item in list) {
            if (item is String) {
              allowlist.add(item);
            }
          }
        }
      }
    }

    String profile = 'security';
    final Map<String, List<String>> profileRules = <String, List<String>>{};
    final YamlMap? profiles = doc['profiles'] as YamlMap?;
    if (profiles != null) {
      final dynamic defaultProfile = profiles['default'];
      if (defaultProfile is String) {
        profile = defaultProfile;
      }
      for (final dynamic key in profiles.keys) {
        if (key is! String || key == 'default') {
          continue;
        }
        final dynamic value = profiles[key];
        if (value is YamlList) {
          profileRules[key] = value.whereType<String>().toList();
        }
      }
    }

    final List<String> webHosts = <String>[];
    final dynamic hosts = doc['webview_allowed_hosts'];
    if (hosts is YamlList) {
      for (final dynamic h in hosts) {
        if (h is String) {
          webHosts.add(h);
        }
      }
    }

    return SastConfig(
      excludeGlobs: globs.toSet().toList(),
      rules: ruleMap,
      exportedAllowlist: allowlist.toSet().toList(),
      profile: profile,
      webviewAllowedHosts: webHosts,
      profileRulePatterns: profileRules,
    );
  }

  RuleConfig? rule(String ruleId) => rules[ruleId];

  /// Config for [ruleId] or its base ID (e.g. `DART-004` for `DART-004b`).
  RuleConfig? ruleConfigFor(String ruleId) {
    final RuleConfig? direct = rule(ruleId);
    if (direct != null) {
      return direct;
    }
    final RegExpMatch? base =
        RegExp(r'^([A-Z]+-\d+)').firstMatch(ruleId);
    if (base != null) {
      return rule(base.group(1)!);
    }
    return null;
  }

  /// Applies per-rule overrides from `.flutter_sast.yml`.
  Vulnerability applyRuleConfig(Vulnerability finding) {
    final RuleConfig? cfg = ruleConfigFor(finding.ruleId);
    if (cfg == null) {
      return finding;
    }
    Vulnerability result = finding;
    if (cfg.severityOverride != null) {
      final Severity? severity = Severity.tryParse(cfg.severityOverride);
      if (severity != null) {
        result = result.copyWith(
          severity: severity,
          scored: severity == Severity.info ? false : result.scored,
        );
      }
    }
    return result;
  }

  bool matchesCustomProfile(String profileName, String ruleId) {
    final List<String>? patterns = profileRulePatterns[profileName];
    if (patterns == null || patterns.isEmpty) {
      return true;
    }
    return patterns.any(
      (String pattern) => ruleIdMatchesProfilePattern(ruleId, pattern),
    );
  }

  /// Whether [relativePath] matches any configured exclude glob.
  bool isExcludedPath(String relativePath) {
    final String normalized = relativePath.replaceAll('\\', '/');
    for (final String pattern in excludeGlobs) {
      if (_globMatches(pattern, normalized)) {
        return true;
      }
    }
    return false;
  }

  bool ruleExcludedForPath(String ruleId, String relativePath) {
    final RuleConfig? cfg = rule(ruleId);
    if (cfg == null) {
      return false;
    }
    for (final String pattern in cfg.excludeGlobs) {
      if (_globMatches(pattern, relativePath.replaceAll('\\', '/'))) {
        return true;
      }
    }
    return false;
  }

  /// Simple `**` glob matching for project paths.
  static bool _globMatches(String pattern, String path) {
    final String ptn = pattern.replaceAll('\\', '/');
    if (ptn == path) {
      return true;
    }
    if (ptn.startsWith('**/')) {
      final String suffix = ptn.substring(3);
      if (suffix.endsWith('/**')) {
        final String prefix = suffix.substring(0, suffix.length - 3);
        return path.contains('/$prefix/') || path.startsWith('$prefix/');
      }
      return path.endsWith(suffix) || path.contains('/$suffix');
    }
    if (ptn.endsWith('/**')) {
      final String prefix = ptn.substring(0, ptn.length - 3);
      return path == prefix ||
          path.startsWith('$prefix/') ||
          path.contains('/$prefix/');
    }
    return path.endsWith(ptn) || path.contains('/$ptn');
  }
}

/// Per-rule overrides from config.
class RuleConfig {
  final List<String> excludeGlobs;
  final String? severityOverride;
  final bool onlySecurityContext;

  const RuleConfig({
    this.excludeGlobs = const <String>[],
    this.severityOverride,
    this.onlySecurityContext = false,
  });

  factory RuleConfig.fromYaml(YamlMap map) {
    final List<String> globs = <String>[];
    final dynamic eg = map['exclude_globs'];
    if (eg is YamlList) {
      for (final dynamic g in eg) {
        if (g is String) {
          globs.add(g);
        }
      }
    }
    return RuleConfig(
      excludeGlobs: globs,
      severityOverride: map['severity'] as String?,
      onlySecurityContext: map['only_security_context'] == true,
    );
  }
}

/// Inline suppression: `// flutter_sast:ignore RULE-ID reason`
final RegExp inlineIgnorePattern = RegExp(
  r'flutter_sast:\s*ignore\s+([A-Z]+-\d+[a-z]?)',
  caseSensitive: false,
);
