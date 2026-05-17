// lib/src/models/finding_confidence.dart

/// How confident the scanner is that a finding is a real issue (not severity).
enum FindingConfidence {
  low,
  medium,
  high;

  String get label {
    switch (this) {
      case FindingConfidence.low:
        return 'LOW';
      case FindingConfidence.medium:
        return 'MEDIUM';
      case FindingConfidence.high:
        return 'HIGH';
    }
  }
}
