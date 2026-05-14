// example/main.dart

import 'dart:io';

import 'package:flutter_sast/flutter_sast.dart';
import 'package:path/path.dart' as p;

Future<void> main() async {
  final String packageRoot = p.normalize(
    p.join(p.dirname(Platform.script.toFilePath()), '..'),
  );

  const ScanOptions options = ScanOptions(
    includeDart: true,
    includeAndroid: true,
    includeIos: true,
    includePubspec: true,
    excludePaths: <String>[
      'build/',
      '.dart_tool/',
      '.pub-cache/',
      'test/',
    ],
    ruleIds: <String>[],
  );

  final FlutterSastScanner scanner =
      FlutterSastScanner(options: options);
  final ScanReport report = await scanner.scan(packageRoot);

  ConsoleReporter().report(report);
  await JsonReporter().writeReport(
    report,
    p.join(packageRoot, 'flutter_sast_report.json'),
  );
  await HtmlReporter().writeReport(
    report,
    p.join(packageRoot, 'flutter_sast_report.html'),
  );

  // ignore: avoid_print
  print('Security score : ${report.securityScore}/100');
  // ignore: avoid_print
  print('Risk level     : ${report.riskLevel}');
  // ignore: avoid_print
  print('Critical       : ${report.criticalCount}');
  // ignore: avoid_print
  print('High           : ${report.highCount}');
  // ignore: avoid_print
  print('Medium         : ${report.mediumCount}');
  // ignore: avoid_print
  print('Low            : ${report.lowCount}');
  // ignore: avoid_print
  print('Info           : ${report.infoCount}');
  // ignore: avoid_print
  print('Files scanned  : ${report.filesScanned}');
  // ignore: avoid_print
  print('Duration (ms)  : ${report.scanDuration.inMilliseconds}');

  // CI integration example: fail the build on any HIGH or CRITICAL finding.
  //
  // import 'dart:io';
  // if (report.criticalCount > 0 || report.highCount > 0) {
  //   exit(1);
  // }
}
