// lib/src/models/report.dart

import 'severity.dart';
import 'vulnerability.dart';

/// Aggregate scan result returned by [FlutterSastScanner.scan].
class ScanReport {
  final String projectPath;
  final DateTime scannedAt;
  final List<Vulnerability> vulnerabilities;
  final int filesScanned;
  final Duration scanDuration;

  const ScanReport({
    required this.projectPath,
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

  /// Composite score clamped to the 0..100 range.
  ///
  /// Starts at 100 and subtracts `severity.score * 4` for every finding.
  int get securityScore {
    var score = 100;
    for (final Vulnerability v in vulnerabilities) {
      score -= v.severity.score * 4;
    }
    if (score < 0) {
      return 0;
    }
    if (score > 100) {
      return 100;
    }
    return score;
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
