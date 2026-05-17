// lib/src/project_info.dart

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

/// Normalized absolute project root and display name from `pubspec.yaml`.
class ProjectInfo {
  final String path;
  final String name;

  const ProjectInfo({required this.path, required this.name});

  static Future<ProjectInfo> resolve(String projectPath) async {
    final String resolved = p.normalize(p.absolute(projectPath));
    String name = p.basename(resolved);
    if (name == '.' || name.isEmpty) {
      name = p.basename(p.dirname(resolved));
    }

    final File pubspec = File(p.join(resolved, 'pubspec.yaml'));
    if (await pubspec.exists()) {
      try {
        final Object? doc = loadYaml(await pubspec.readAsString());
        if (doc is YamlMap) {
          final Object? raw = doc['name'];
          if (raw is String && raw.trim().isNotEmpty) {
            name = raw.trim();
          }
        }
      } on Object {
        // Keep directory basename when pubspec is unreadable.
      }
    }

    return ProjectInfo(path: resolved, name: name);
  }
}
