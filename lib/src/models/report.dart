// lib/src/models/report.dart

import 'severity.dart';
import 'vulnerability.dart';

/// Aggregate scan result returned by [FlutterSastScanner.scan].
class ScanReport {
  /// Absolute path to the scanned project root.
  final String projectPath;

  /// Package name from `pubspec.yaml`, or the project directory name.
  final String projectName;

  final DateTime scannedAt;
  final List<Vulnerability> vulnerabilities;
  final int filesScanned;
  final Duration scanDuration;

  const ScanReport({
    required this.projectPath,
    required this.projectName,
    required this.scannedAt,
    required this.vulnerabilities,
    required this.filesScanned,
    required this.scanDuration,
  });

  int get criticalCount => _countBy(Severity.critical);
  int get highCount => _countBy(Severity.high);
  int get mediumCount => _countBy(Severity.medium);
  int get lowCount => _countBy(Severity.low);
  int get infoCount => _countBy(Severity.info);

  int _countBy(Severity severity) =>
      vulnerabilities.where((Vulnerability v) => v.severity == severity).length;

  /// Heuristic hygiene score (0–100), not exploitability.
  ///
  /// Findings reduce the score with capped deductions so advisory noise
  /// (INFO/LOW) does not collapse real projects to 0/100.
  int get securityScore {
    if (vulnerabilities.isEmpty) {
      return 100;
    }
    var deducted = 0;
    for (final Vulnerability v in vulnerabilities) {
      deducted += switch (v.severity) {
        Severity.critical => 15,
        Severity.high => 7,
        Severity.medium => 4,
        Severity.low => 2,
        Severity.info => 0,
      };
    }
    return 100 - deducted.clamp(0, 75);
  }

  /// Highest severity present in the report, or `CLEAN`.
  String get riskLevel {
    if (criticalCount > 0) {
      return 'CRITICAL';
    }
    if (highCount > 0) {
      return 'HIGH';
    }
    if (mediumCount > 0) {
      return 'MEDIUM';
    }
    if (lowCount > 0) {
      return 'LOW';
    }
    return 'CLEAN';
  }

  Map<String, dynamic> toJson() {
    return <String, dynamic>{
      'projectPath': projectPath,
      'projectName': projectName,
      'scannedAt': scannedAt.toIso8601String(),
      'filesScanned': filesScanned,
      'scanDurationMs': scanDuration.inMilliseconds,
      'securityScore': securityScore,
      'riskLevel': riskLevel,
      'summary': <String, dynamic>{
        'total': vulnerabilities.length,
        'critical': criticalCount,
        'high': highCount,
        'medium': mediumCount,
        'low': lowCount,
        'info': infoCount,
      },
      'vulnerabilities':
          vulnerabilities.map((Vulnerability v) => v.toJson()).toList(),
    };
  }
}
