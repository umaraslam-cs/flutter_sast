// bin/flutter_sast.dart

import 'dart:io';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';

import 'package:flutter_sast/flutter_sast.dart';

const String _version = '0.1.0';

const String _ansiBoldPurple = '\x1B[1;35m';
const String _ansiRed = '\x1B[31m';
const String _ansiReset = '\x1B[0m';

void _registerScanOptions(ArgParser parser) {
  parser
    ..addOption(
      'output',
      abbr: 'o',
      help: 'Output file path for json / html reports.',
    )
    ..addMultiOption(
      'format',
      abbr: 'f',
      allowed: <String>['console', 'json', 'html'],
      defaultsTo: <String>['console'],
      help: 'One or more output formats.',
    )
    ..addMultiOption(
      'exclude',
      abbr: 'e',
      defaultsTo: const <String>[
        'build/',
        '.dart_tool/',
        '.pub-cache/',
        'test/',
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
      'Run SAST rules against a Flutter / Dart project root.';

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

    stdout.writeln(
      '${_ansiBoldPurple}flutter_sast  Scanning $projectPath ...$_ansiReset',
    );

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
      stderr.writeln('${_ansiRed}Scan failed:$_ansiReset $e');
      return 2;
    }

    final bool wantsConsole = formats.contains('console');
    final bool wantsJson = formats.contains('json') ||
        (output != null && output.endsWith('.json'));
    final bool wantsHtml = formats.contains('html') ||
        (output != null && output.endsWith('.html'));

    if (wantsConsole) {
      ConsoleReporter().report(report);
    }
    if (wantsJson) {
      final String target = output != null && output.endsWith('.json')
          ? output
          : 'flutter_sast_report.json';
      await JsonReporter().writeReport(report, target);
      stdout.writeln('JSON report written to $target');
    }
    if (wantsHtml) {
      final String target = output != null && output.endsWith('.html')
          ? output
          : 'flutter_sast_report.html';
      await HtmlReporter().writeReport(report, target);
      stdout.writeln('HTML report written to $target');
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

Future<void> main(List<String> arguments) async {
  if (arguments.length == 1 &&
      (arguments.first == '-v' || arguments.first == '--version')) {
    stdout.writeln('flutter_sast $_version');
    exit(0);
  }

  final FlutterSastCommandRunner runner = FlutterSastCommandRunner();
  try {
    final int exitCode = await runner.run(arguments) ?? 0;
    exit(exitCode);
  } on UsageException catch (e) {
    stderr.writeln('${_ansiRed}Error:$_ansiReset ${e.message}');
    stderr.writeln(e.usage);
    exit(1);
  }
}
