// lib/src/reporters/html_reporter.dart

import 'dart:io';

import '../models/report.dart';
import '../version.dart';
import '../models/severity.dart';
import '../models/vulnerability.dart';

/// Writes the scan report as a fully self-contained HTML document.
class HtmlReporter {
  Future<void> writeReport(ScanReport report, String outputPath) async {
    final File file = File(outputPath);
    await file.parent.create(recursive: true);
    await file.writeAsString(_buildHtml(report));
  }

  String _buildHtml(ScanReport report) {
    final StringBuffer body = StringBuffer();

    body.writeln(_header(report));
    body.writeln(_scoreGrid(report));

    if (report.vulnerabilities.isEmpty) {
      body.writeln(
        '<div class="empty">✅ No vulnerabilities found!</div>',
      );
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
        body.writeln(_section(severity, group));
      }
    }

    body.writeln(_footer());

    return _document(report, body.toString());
  }

  String _document(ScanReport report, String body) {
    return '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>flutter_sast | ${_escape(report.projectPath)}</title>
<style>
:root {
  --bg: #0f1117;
  --surface: #1a1d2e;
  --surface2: #242740;
  --border: #2e3154;
  --text: #e2e8f0;
  --dim: #94a3b8;
  --critical: #a855f7;
  --high: #ef4444;
  --medium: #f59e0b;
  --low: #3b82f6;
  --info: #06b6d4;
  --green: #22c55e;
  --accent: #7c3aed;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 32px;
  background: var(--bg);
  color: var(--text);
  font-family: 'SF Mono', 'Fira Code', monospace;
  line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
header.report {
  margin-bottom: 24px;
}
header.report h1 {
  margin: 0 0 8px;
  color: var(--accent);
  font-size: 24px;
}
header.report .meta {
  color: var(--dim);
  font-size: 13px;
}
.score-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin: 24px 0;
}
.score-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}
.score-card .label {
  font-size: 12px;
  color: var(--dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.score-card .value {
  font-size: 28px;
  font-weight: 700;
  margin-top: 6px;
}
.score-card.critical .value { color: var(--critical); }
.score-card.high .value { color: var(--high); }
.score-card.medium .value { color: var(--medium); }
.score-card.low .value { color: var(--low); }
.score-card.info .value { color: var(--info); }
.score-card.score-green .value { color: var(--green); }
.score-card.score-yellow .value { color: var(--medium); }
.score-card.score-red .value { color: var(--high); }
.empty {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 48px;
  text-align: center;
  color: var(--green);
  font-size: 20px;
  font-weight: 600;
}
section.findings {
  margin-top: 32px;
}
section.findings h2 {
  font-size: 16px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin: 0 0 12px;
}
section.findings.critical h2 { color: var(--critical); }
section.findings.high h2 { color: var(--high); }
section.findings.medium h2 { color: var(--medium); }
section.findings.low h2 { color: var(--low); }
section.findings.info h2 { color: var(--info); }
.finding {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 4px solid transparent;
  border-radius: 6px;
  padding: 16px;
  margin-bottom: 12px;
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding .head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: white;
}
.badge.critical { background: var(--critical); }
.badge.high { background: var(--high); }
.badge.medium { background: var(--medium); color: #1a1d2e; }
.badge.low { background: var(--low); }
.badge.info { background: var(--info); color: #1a1d2e; }
.rule-id {
  font-weight: 700;
  color: var(--accent);
  font-size: 13px;
}
.finding .title {
  font-size: 15px;
  font-weight: 600;
}
.finding .meta {
  font-size: 12px;
  color: var(--dim);
  margin-bottom: 8px;
}
.finding .description {
  font-size: 13px;
  margin: 8px 0;
}
.fix {
  background: rgba(34, 197, 94, 0.1);
  border-left: 3px solid var(--green);
  border-radius: 4px;
  padding: 8px 12px;
  font-size: 13px;
  margin: 8px 0;
  color: var(--green);
}
.snippet {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 10px 12px;
  font-size: 12px;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-all;
  margin-top: 8px;
}
footer.report {
  margin-top: 48px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  text-align: center;
  color: var(--dim);
  font-size: 12px;
}
</style>
</head>
<body>
$body
</body>
</html>
''';
  }

  String _header(ScanReport report) {
    return '''
<header class="report">
  <h1>flutter_sast | Security Scan Report</h1>
  <div class="meta">
    <div><strong>Project:</strong> ${_escape(report.projectPath)}</div>
    <div><strong>Scanned:</strong> ${_escape(report.scannedAt.toIso8601String())}</div>
    <div><strong>Files scanned:</strong> ${report.filesScanned}</div>
    <div><strong>Duration:</strong> ${report.scanDuration.inMilliseconds} ms</div>
  </div>
</header>
''';
  }

  String _scoreGrid(ScanReport report) {
    String scoreClass;
    if (report.securityScore >= 80) {
      scoreClass = 'score-green';
    } else if (report.securityScore >= 50) {
      scoreClass = 'score-yellow';
    } else {
      scoreClass = 'score-red';
    }

    return '''
<div class="score-grid">
  <div class="score-card $scoreClass">
    <div class="label">Score</div>
    <div class="value">${report.securityScore}/100</div>
  </div>
  <div class="score-card critical">
    <div class="label">Critical</div>
    <div class="value">${report.criticalCount}</div>
  </div>
  <div class="score-card high">
    <div class="label">High</div>
    <div class="value">${report.highCount}</div>
  </div>
  <div class="score-card medium">
    <div class="label">Medium</div>
    <div class="value">${report.mediumCount}</div>
  </div>
  <div class="score-card low">
    <div class="label">Low</div>
    <div class="value">${report.lowCount}</div>
  </div>
  <div class="score-card info">
    <div class="label">Info</div>
    <div class="value">${report.infoCount}</div>
  </div>
</div>
''';
  }

  String _section(Severity severity, List<Vulnerability> group) {
    final String klass = severity.label.toLowerCase();
    final StringBuffer buf = StringBuffer();
    buf.writeln('<section class="findings $klass">');
    buf.writeln(
      '<h2>${_escape(severity.label)} (${group.length})</h2>',
    );
    for (final Vulnerability v in group) {
      buf.writeln(_finding(v));
    }
    buf.writeln('</section>');
    return buf.toString();
  }

  String _finding(Vulnerability v) {
    final String klass = v.severity.label.toLowerCase();
    final String location = v.lineNumber != null
        ? '${v.filePath}:${v.lineNumber}'
        : v.filePath;
    final StringBuffer buf = StringBuffer();
    buf.writeln('<div class="finding $klass">');
    buf.writeln('  <div class="head">');
    buf.writeln(
        '    <span class="badge $klass">${_escape(v.severity.label)}</span>');
    buf.writeln('    <span class="rule-id">${_escape(v.ruleId)}</span>');
    buf.writeln('    <span class="title">${_escape(v.title)}</span>');
    buf.writeln('  </div>');
    final StringBuffer metaParts = StringBuffer();
    metaParts.write('<strong>File:</strong> ${_escape(location)}');
    metaParts.write('  &middot;  ');
    metaParts.write('<strong>Category:</strong> ${_escape(v.category)}');
    if (v.cwe != null) {
      metaParts.write('  &middot;  ');
      metaParts.write('<strong>CWE:</strong> ${_escape(v.cwe!)}');
    }
    if (v.owasp != null) {
      metaParts.write('  &middot;  ');
      metaParts.write('<strong>OWASP:</strong> ${_escape(v.owasp!)}');
    }
    buf.writeln('  <div class="meta">${metaParts.toString()}</div>');
    buf.writeln(
        '  <div class="description">${_escape(v.description)}</div>');
    buf.writeln(
        '  <div class="fix"><strong>💡 Fix:</strong> ${_escape(v.recommendation)}</div>');
    if (v.snippet != null && v.snippet!.isNotEmpty) {
      buf.writeln('  <pre class="snippet">${_escape(v.snippet!)}</pre>');
    }
    buf.writeln('</div>');
    return buf.toString();
  }

  String _footer() {
    return '''
<footer class="report">
  flutter_sast v$packageVersion &middot;
  <a href="https://github.com/umaraslam-cs/flutter_sast">github.com/umaraslam-cs/flutter_sast</a>
</footer>
''';
  }

  String _escape(String value) {
    return value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
  }
}
