// bin/flutter_sast.dart

import 'dart:io';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:path/path.dart' as p;

import 'package:flutter_sast/flutter_sast.dart';
import 'package:flutter_sast/src/version.dart';

const String _ansiBoldPurple = '\x1B[1;35m';
const String _ansiRed = '\x1B[31m';
const String _ansiReset = '\x1B[0m';

void _writeStderr(String message, {bool errorPrefix = false}) {
  if (stderr.hasTerminal) {
    if (errorPrefix) {
      stderr.writeln('${_ansiRed}Error:$_ansiReset $message');
    } else {
      stderr.writeln('$_ansiRed$message$_ansiReset');
    }
  } else {
    stderr.writeln(errorPrefix ? 'Error: $message' : message);
  }
}

void _registerScanOptions(ArgParser parser) {
  parser
    ..addOption(
      'output',
      abbr: 'o',
      help:
          'Report path: a .json/.html file, a directory (e.g. ./reports/), '
          'or a basename (writes .json and .html alongside).',
    )
    ..addFlag(
      'quiet',
      abbr: 'q',
      negatable: false,
      defaultsTo: false,
      help: 'Skip console output (file reports only).',
    )
    ..addMultiOption(
      'format',
      abbr: 'f',
      allowed: <String>['console', 'json', 'html'],
      defaultsTo: <String>['console', 'json', 'html'],
      help:
          'Output formats (default: console, json, and html). '
          'Example: -f json for JSON only.',
    )
    ..addMultiOption(
      'exclude',
      abbr: 'e',
      defaultsTo: const <String>[
        'build/',
        '.dart_tool/',
        '.pub-cache/',
        'test/',
        'example/',
      ],
      help: 'Path prefixes (relative to project root) to skip.',
    )
    ..addMultiOption(
      'rules',
      abbr: 'r',
      defaultsTo: const <String>[],
      help: 'Restrict scan to specific rule IDs (e.g. DART-001).',
    )
    ..addFlag(
      'dart',
      negatable: true,
      defaultsTo: true,
      help: 'Analyze Dart source files. Use --no-dart to skip.',
    )
    ..addFlag(
      'android',
      negatable: true,
      defaultsTo: true,
      help: 'Analyze AndroidManifest.xml. Use --no-android to skip.',
    )
    ..addFlag(
      'ios',
      negatable: true,
      defaultsTo: true,
      help: 'Analyze ios/Runner/Info.plist. Use --no-ios to skip.',
    )
    ..addFlag(
      'pubspec',
      negatable: true,
      defaultsTo: true,
      help: 'Analyze pubspec.yaml dependencies. Use --no-pubspec to skip.',
    )
    ..addFlag(
      'fail-on-high',
      negatable: false,
      defaultsTo: false,
      help: 'Exit with status 1 if any HIGH or CRITICAL finding exists.',
    )
    ..addFlag(
      'fail-on-any',
      negatable: false,
      defaultsTo: false,
      help: 'Exit with status 1 if any finding exists.',
    );
}

/// Root command runner; use subcommand [ScanCommand].
class FlutterSastCommandRunner extends CommandRunner<int> {
  FlutterSastCommandRunner()
      : super(
          'flutter_sast',
          'SAST and vulnerability assessment for Flutter / Dart projects.',
        ) {
    addCommand(ScanCommand());
  }

  @override
  String? get usageFooter =>
      'https://github.com/umaraslam-cs/flutter_sast';

  /// `flutter_sast` and `flutter_sast .` run [ScanCommand] without typing `scan`.
  @override
  Future<int?> run(Iterable<String> args) {
    return Future.sync(() => runCommand(parse(_effectiveArgs(args.toList()))));
  }

  List<String> _effectiveArgs(List<String> argList) {
    if (argList.isEmpty) {
      return <String>['scan'];
    }
    if (argList.first != 'scan' && !commands.containsKey(argList.first)) {
      return <String>['scan', ...argList];
    }
    return argList;
  }
}

/// `flutter_sast scan [directory]` — optional project root (default `.`).
class ScanCommand extends Command<int> {
  ScanCommand() {
    _registerScanOptions(argParser);
  }

  @override
  String get name => 'scan';

  @override
  String get description =>
      'Run SAST rules; console + JSON + HTML reports by default.';

  @override
  String get invocation => '${super.invocation} [directory]';

  @override
  bool get takesArguments => true;

  @override
  Future<int> run() async {
    final ArgResults args = argResults!;
    final List<String> rest = args.rest;
    if (rest.length > 1) {
      usageException(
        'At most one directory argument is allowed (found: ${rest.join(", ")}).',
      );
    }
    final String projectPath = rest.isNotEmpty ? rest.first : '.';

    final String? output = args['output'] as String?;
    final List<String> formats = args['format'] as List<String>;
    final List<String> exclude = args['exclude'] as List<String>;
    final List<String> rules = args['rules'] as List<String>;
    final bool includeDart = args['dart'] as bool;
    final bool includeAndroid = args['android'] as bool;
    final bool includeIos = args['ios'] as bool;
    final bool includePubspec = args['pubspec'] as bool;
    final bool failOnHigh = args['fail-on-high'] as bool;
    final bool failOnAny = args['fail-on-any'] as bool;
    final bool quiet = args['quiet'] as bool;
    final bool formatExplicit = args.wasParsed('format');

    final bool wantsConsole = formats.contains('console') &&
        !quiet &&
        (stdout.hasTerminal || formatExplicit);
    final bool wantsJson = formats.contains('json') ||
        (output != null && output.endsWith('.json'));
    final bool wantsHtml = formats.contains('html') ||
        (output != null && output.endsWith('.html'));

    if (!quiet && stdout.hasTerminal) {
      stdout.writeln(
        '${_ansiBoldPurple}flutter_sast  Scanning $projectPath ...$_ansiReset',
      );
    } else if (!quiet) {
      stderr.writeln('flutter_sast  Scanning $projectPath ...');
    }

    final ScanOptions options = ScanOptions(
      includeDart: includeDart,
      includeAndroid: includeAndroid,
      includeIos: includeIos,
      includePubspec: includePubspec,
      excludePaths: exclude,
      ruleIds: rules,
    );

    final ScanReport report;
    try {
      report = await FlutterSastScanner(options: options).scan(projectPath);
    } on Object catch (e) {
      _writeStderr('Scan failed: $e', errorPrefix: true);
      return 2;
    }

    if (wantsConsole) {
      ConsoleReporter().report(report);
    }
    if (wantsJson) {
      final String target = _resolveReportPath(
        projectPath: projectPath,
        output: output,
        extension: '.json',
        defaultName: 'flutter_sast_report.json',
      );
      await JsonReporter().writeReport(report, target);
      _writeStatus('JSON report → $target', quiet: quiet);
    }
    if (wantsHtml) {
      final String target = _resolveReportPath(
        projectPath: projectPath,
        output: output,
        extension: '.html',
        defaultName: 'flutter_sast_report.html',
      );
      await HtmlReporter().writeReport(report, target);
      _writeStatus('HTML report → $target', quiet: quiet);
    }

    if (failOnAny && report.vulnerabilities.isNotEmpty) {
      return 1;
    }
    if (failOnHigh && (report.criticalCount > 0 || report.highCount > 0)) {
      return 1;
    }

    return 0;
  }
}

void _writeStatus(String message, {required bool quiet}) {
  if (quiet || !stdout.hasTerminal) {
    stderr.writeln(message);
  } else {
    stdout.writeln(message);
  }
}

/// Resolves the JSON/HTML report path under [projectPath] unless [-o] targets
/// that extension, a directory, or a shared basename.
String _resolveReportPath({
  required String projectPath,
  required String? output,
  required String extension,
  required String defaultName,
}) {
  if (output == null) {
    return p.join(projectPath, defaultName);
  }
  if (output.endsWith(extension)) {
    return output;
  }

  final String siblingExt = extension == '.json' ? '.html' : '.json';
  if (output.endsWith(siblingExt)) {
    return p.join(p.dirname(output), defaultName);
  }

  if (output.endsWith('/') || output.endsWith(r'\')) {
    return p.join(output, defaultName);
  }

  if (p.extension(output).isEmpty) {
    if (Directory(output).existsSync()) {
      return p.join(output, defaultName);
    }
    return '$output$extension';
  }

  return p.join(projectPath, defaultName);
}

Future<void> main(List<String> arguments) async {
  if (arguments.length == 1 &&
      (arguments.first == '-v' || arguments.first == '--version')) {
    stdout.writeln('flutter_sast $packageVersion');
    exit(0);
  }

  final FlutterSastCommandRunner runner = FlutterSastCommandRunner();
  try {
    final int exitCode = await runner.run(arguments) ?? 0;
    exit(exitCode);
  } on UsageException catch (e) {
    _writeStderr(e.message, errorPrefix: true);
    stderr.writeln(e.usage);
    exit(1);
  }
}
