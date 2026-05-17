// lib/src/reporters/console_reporter.dart

import 'dart:io';

import '../models/report.dart';
import '../version.dart';
import '../models/severity.dart';
import '../models/vulnerability.dart';

const String _reset = '\x1B[0m';
const String _bold = '\x1B[1m';
const String _dim = '\x1B[2m';
const String _green = '\x1B[32m';
const String _red = '\x1B[31m';
const String _yellow = '\x1B[33m';
const String _magenta = '\x1B[35m';

const String _sep =
    '════════════════════════════════════════════════════════════════════';

/// Prints a human-readable summary of a [ScanReport] to stdout.
class ConsoleReporter {
  final bool useColor;

  /// When [useColor] is omitted it defaults to `stdout.hasTerminal` so that
  /// piped output (e.g. `flutter_sast scan > report.txt`) does not contain
  /// raw ANSI escape codes.
  ConsoleReporter({bool? useColor}) : useColor = useColor ?? stdout.hasTerminal;

  void report(ScanReport report) {
    final StringBuffer out = StringBuffer();

    out.writeln(_c(_sep, _magenta));
    out.writeln(
      _c('${_bold}flutter_sast | Security Scan Report$_reset', _magenta),
    );
    out.writeln(_c(_sep, _magenta));
    out.writeln('Project   : ${report.projectPath}');
    out.writeln('Scanned   : ${report.scannedAt.toIso8601String()}');
    out.writeln('Files     : ${report.filesScanned}');
    out.writeln('Duration  : ${report.scanDuration.inMilliseconds} ms');
    out.writeln('');

    final String scoreColor = report.securityScore >= 80
        ? _green
        : report.securityScore >= 50
            ? _yellow
            : _red;
    final String riskColor = _riskColor(report.riskLevel);

    final String scoreText = _c('${report.securityScore}/100', scoreColor);
    final String riskText = _c(report.riskLevel, riskColor);
    out.writeln('${_bold}Security Score : $_reset$scoreText');
    out.writeln('${_bold}Risk Level     : $_reset$riskText');
    out.writeln('');

    out.writeln('${_bold}Findings by severity:$_reset');
    _printCount(out, 'CRITICAL', report.criticalCount, Severity.critical);
    _printCount(out, 'HIGH    ', report.highCount, Severity.high);
    _printCount(out, 'MEDIUM  ', report.mediumCount, Severity.medium);
    _printCount(out, 'LOW     ', report.lowCount, Severity.low);
    _printCount(out, 'INFO    ', report.infoCount, Severity.info);
    out.writeln('');

    if (report.vulnerabilities.isEmpty) {
      out.writeln(_c(
        '✅ No vulnerabilities found. Looks good.',
        _green,
      ));
    } else {
      for (final Severity severity in <Severity>[
        Severity.critical,
        Severity.high,
        Severity.medium,
        Severity.low,
        Severity.info,
      ]) {
        final List<Vulnerability> group = report.vulnerabilities
            .where((Vulnerability v) => v.severity == severity)
            .toList();
        if (group.isEmpty) {
          continue;
        }
        out.writeln(_c('--- ${severity.label} (${group.length}) ---',
            severity.ansiColor));
        out.writeln('');
        for (final Vulnerability v in group) {
          _writeFinding(out, v);
        }
      }
    }

    out.writeln(_c(_sep, _magenta));
    out.writeln('${_dim}flutter_sast v$packageVersion$_reset');
    out.writeln('${_dim}https://github.com/umaraslam-cs/flutter_sast$_reset');
    out.writeln(_c(_sep, _magenta));

    stdout.write(out.toString());
  }

  void _printCount(
      StringBuffer out, String label, int count, Severity severity) {
    if (count == 0) {
      out.writeln('  ${_c(label, _dim)} : ${_c('0', _dim)}');
    } else {
      out.writeln(
          '  ${_c(label, severity.ansiColor)} : ${_c('$count', severity.ansiColor)}');
    }
  }

  void _writeFinding(StringBuffer out, Vulnerability v) {
    final String sevColor = v.severity.ansiColor;
    final String sevTag = _c('[${v.severity.label}]', sevColor);
    out.writeln('$sevTag $_bold${v.ruleId}$_reset  ${v.title}');
    final String location = v.lineNumber != null
        ? '${v.filePath}:${v.lineNumber}'
        : v.filePath;
    out.writeln('  ${_dim}File$_reset       : $location');
    out.writeln('  ${_dim}Category$_reset   : ${v.category}');
    if (v.cwe != null) {
      out.writeln('  ${_dim}CWE$_reset        : ${v.cwe}');
    }
    if (v.owasp != null) {
      out.writeln('  ${_dim}OWASP$_reset      : ${v.owasp}');
    }
    final String descBody = _wrap(v.description, 56, '    ');
    final String fixBody = _wrap(v.recommendation, 56, '    ');
    out.writeln('  ${_dim}Description$_reset:\n$descBody');
    out.writeln('  $_dim💡 Fix:$_reset\n$fixBody');
    if (v.snippet != null && v.snippet!.isNotEmpty) {
      out.writeln('  ${_dim}Snippet$_reset    :');
      out.writeln('  ┌${'─' * 64}');
      for (final String line in v.snippet!.split('\n')) {
        out.writeln('  │ $line');
      }
      out.writeln('  └${'─' * 64}');
    }
    out.writeln('');
  }

  String _riskColor(String risk) {
    switch (risk) {
      case 'CRITICAL':
        return _magenta;
      case 'HIGH':
        return _red;
      case 'MEDIUM':
        return _yellow;
      case 'LOW':
        return '\x1B[34m';
      case 'CLEAN':
        return _green;
      default:
        return _reset;
    }
  }

  String _c(String text, String color) {
    if (!useColor) {
      return text;
    }
    return '$color$text$_reset';
  }

  String _wrap(String text, int width, String indent) {
    final List<String> words = text.split(RegExp(r'\s+'));
    final StringBuffer result = StringBuffer();
    final StringBuffer current = StringBuffer(indent);
    int lineLen = 0;
    for (final String word in words) {
      if (word.isEmpty) {
        continue;
      }
      if (lineLen + word.length + 1 > width && lineLen > 0) {
        result.writeln(current.toString());
        current
          ..clear()
          ..write(indent);
        lineLen = 0;
      }
      if (lineLen > 0) {
        current.write(' ');
        lineLen += 1;
      }
      current.write(word);
      lineLen += word.length;
    }
    if (lineLen > 0) {
      result.write(current.toString());
    }
    return result.toString();
  }
}
