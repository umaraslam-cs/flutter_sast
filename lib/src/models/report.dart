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
  /// `100 - sum(severityWeight × confidenceMultiplier)` for [Vulnerability.scored]
  /// findings. INFO and Recommendation-category findings are excluded.
  int get securityScore {
  final List<Vulnerability> scoredFindings = vulnerabilities
      .where((Vulnerability v) => v.scored && v.severity != Severity.info)
      .toList();
    if (scoredFindings.isEmpty) {
      return 100;
    }
    var deducted = 0.0;
    for (final Vulnerability v in scoredFindings) {
      final double weight = switch (v.severity) {
        Severity.critical => 25.0,
        Severity.high => 10.0,
        Severity.medium => 3.0,
        Severity.low => 1.0,
        Severity.info => 0.0,
      };
      deducted += weight * v.confidence.scoreMultiplier;
    }
    return (100 - deducted.round()).clamp(0, 100);
  }

  int get recommendationCount => vulnerabilities
      .where((Vulnerability v) => v.category == 'Recommendation')
      .length;

  /// Highest severity present in the report, or `CLEAN` / `ADVISORY`.
  ///
  /// `ADVISORY` means only dependency hints (DEPS-*) — no code or platform
  /// findings at HIGH or above.
  String get riskLevel {
    if (vulnerabilities.isEmpty) {
      return 'CLEAN';
    }
    if (_onlyDependencyAdvisories && criticalCount == 0 && highCount == 0) {
      return 'ADVISORY';
    }
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

  bool get _onlyDependencyAdvisories => vulnerabilities.every(
        (Vulnerability v) =>
            v.ruleId.startsWith('DEPS-') || v.category == 'Recommendation',
      );

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
