// lib/src/reporters/json_reporter.dart

import 'dart:convert';
import 'dart:io';

import '../models/report.dart';

/// Writes the scan report as pretty-printed JSON.
class JsonReporter {
  static const JsonEncoder _encoder = JsonEncoder.withIndent('  ');

  Future<void> writeReport(ScanReport report, String outputPath) async {
    final File file = File(outputPath);
    await file.parent.create(recursive: true);
    await file.writeAsString(_encoder.convert(report.toJson()));
  }

  String toJsonString(ScanReport report) {
    return _encoder.convert(report.toJson());
  }
}
