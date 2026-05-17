import 'dart:io';

import 'package:flutter_sast/src/project_info.dart';
import 'package:test/test.dart';

void main() {
  test('resolve uses pubspec name and absolute path', () async {
    final Directory dir = await Directory.systemTemp.createTemp('fsast_proj_');
    addTearDown(() => dir.deleteSync(recursive: true));

    File('${dir.path}/pubspec.yaml').writeAsStringSync('''
name: my_flutter_app
version: 1.0.0
dependencies:
  flutter:
    sdk: flutter
''');

    final ProjectInfo info = await ProjectInfo.resolve(dir.path);
    expect(info.name, 'my_flutter_app');
    expect(info.path, isNot(endsWith('.')));
    expect(Directory(info.path).existsSync(), isTrue);
    expect(info.isFlutterApplication, isTrue);
  });

  test('CLI package without flutter SDK is not a Flutter application', () async {
    final Directory dir = await Directory.systemTemp.createTemp('fsast_cli_');
    addTearDown(() => dir.deleteSync(recursive: true));

    File('${dir.path}/pubspec.yaml').writeAsStringSync('''
name: my_cli
dependencies:
  args: ^2.0.0
executables:
  my_cli: my_cli
''');

    final ProjectInfo info = await ProjectInfo.resolve(dir.path);
    expect(info.isFlutterApplication, isFalse);
  });
}
