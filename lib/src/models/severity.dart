// lib/src/models/severity.dart

/// Severity classification for a [Vulnerability].
enum Severity {
  critical,
  high,
  medium,
  low,
  info;

  /// Human-readable upper-case label, e.g. `CRITICAL`.
  String get label {
    switch (this) {
      case Severity.critical:
        return 'CRITICAL';
      case Severity.high:
        return 'HIGH';
      case Severity.medium:
        return 'MEDIUM';
      case Severity.low:
        return 'LOW';
      case Severity.info:
        return 'INFO';
    }
  }

  /// Raw ANSI color escape used for terminal output.
  String get ansiColor {
    switch (this) {
      case Severity.critical:
        return '\x1B[35m';
      case Severity.high:
        return '\x1B[31m';
      case Severity.medium:
        return '\x1B[33m';
      case Severity.low:
        return '\x1B[34m';
      case Severity.info:
        return '\x1B[36m';
    }
  }

  /// Numeric weight used for scoring and ordering.
  ///
  /// Higher values indicate a more severe finding.
  int get score {
    switch (this) {
      case Severity.critical:
        return 5;
      case Severity.high:
        return 4;
      case Severity.medium:
        return 3;
      case Severity.low:
        return 2;
      case Severity.info:
        return 1;
    }
  }
}
