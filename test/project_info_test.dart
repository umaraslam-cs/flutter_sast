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
''');

    final ProjectInfo info = await ProjectInfo.resolve(dir.path);
    expect(info.name, 'my_flutter_app');
    expect(info.path, isNot(endsWith('.')));
    expect(Directory(info.path).existsSync(), isTrue);
  });
}
