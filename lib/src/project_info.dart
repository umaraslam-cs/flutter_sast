// lib/src/project_info.dart

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

/// Normalized absolute project root and display name from `pubspec.yaml`.
class ProjectInfo {
  final String path;
  final String name;

  /// Flutter/mobile-style app (has `flutter` SDK dep), not a CLI-only package.
  final bool isFlutterApplication;

  const ProjectInfo({
    required this.path,
    required this.name,
    required this.isFlutterApplication,
  });

  static Future<ProjectInfo> resolve(String projectPath) async {
    final String resolved = p.normalize(p.absolute(projectPath));
    String name = p.basename(resolved);
    if (name == '.' || name.isEmpty) {
      name = p.basename(p.dirname(resolved));
    }

    var isFlutterApplication = false;

    final File pubspec = File(p.join(resolved, 'pubspec.yaml'));
    if (await pubspec.exists()) {
      try {
        final Object? doc = loadYaml(await pubspec.readAsString());
        if (doc is YamlMap) {
          final Object? raw = doc['name'];
          if (raw is String && raw.trim().isNotEmpty) {
            name = raw.trim();
          }
          isFlutterApplication = _dependsOnFlutterSdk(doc);
        }
      } on Object {
        // Keep directory basename when pubspec is unreadable.
      }
    }

    return ProjectInfo(
      path: resolved,
      name: name,
      isFlutterApplication: isFlutterApplication,
    );
  }

  static bool _dependsOnFlutterSdk(YamlMap doc) {
    for (final String section in <String>['dependencies', 'dev_dependencies']) {
      final Object? deps = doc[section];
      if (deps is YamlMap && deps.containsKey('flutter')) {
        return true;
      }
    }
    return false;
  }
}
