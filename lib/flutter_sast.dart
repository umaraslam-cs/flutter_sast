// lib/flutter_sast.dart

/// flutter_sast — SAST and vulnerability assessment for Flutter / Dart.
///
/// Public surface of the package. Import this barrel to use the scanner
/// and reporters programmatically.
library flutter_sast;

export 'src/scanner.dart' show FlutterSastScanner, ScanOptions;
export 'src/models/report.dart' show ScanReport;
export 'src/models/vulnerability.dart' show Vulnerability;
export 'src/models/severity.dart' show Severity;
export 'src/reporters/console_reporter.dart' show ConsoleReporter;
export 'src/reporters/json_reporter.dart' show JsonReporter;
export 'src/reporters/html_reporter.dart' show HtmlReporter;
