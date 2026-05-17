// lib/src/analysis/line_context.dart

/// Lightweight line classification to reduce regex false positives.
enum LineContextKind {
  uiString,
  config,
  logging,
  network,
  securitySink,
  testMock,
  storage,
  general,
}

/// Heuristic context helpers shared by Dart rules.
abstract final class LineContext {
  static final RegExp _mockToken = RegExp(
    r'\b(?:test|mock|sample|demo|placeholder|fake|dummy|stub)\b',
    caseSensitive: false,
  );

  static final RegExp _mockValueLiteral = RegExp(
    r'''["'](?:test|mock|example|sample|demo|placeholder|fake)[_a-zA-Z0-9]*["']''',
    caseSensitive: false,
  );

  static final RegExp _uiLabel = RegExp(
    r'''(?:Text\s*\(|label:\s*|hintText:\s*|title:\s*|AppBar\s*\()''',
    caseSensitive: false,
  );

  static final RegExp _uiScreenPhrase = RegExp(
    r'''["'](?:Enter |.*(?:screen|opened|clicked|hint))''',
    caseSensitive: false,
  );

  static final RegExp _logCall =
      RegExp(r'(?:print|debugPrint|log)\s*\(');

  static final RegExp _prefsWrite = RegExp(
    r'(?:SharedPreferences|prefs)\b.*\.(?:setString|setInt|setBool)\s*\(',
  );

  /// High-risk preference / storage key fragments.
  static final RegExp prefsHighRiskKey = RegExp(
    r'\b(?:access[_-]?token|refresh[_-]?token|jwt|bearer|api[_-]?key|'
    r'private[_-]?key|secret|password|passwd|credential|entitlement)\b',
    caseSensitive: false,
  );

  /// Benign key fragments (UI state, counters, flow flags).
  static final RegExp prefsBenignKey = RegExp(
    r'(?:screen|hint|button|clicked|opened|retry|_count|_seen|ui_|flag|'
    r'flow|metadata|session_count|last_session|review)',
    caseSensitive: false,
  );

  static final RegExp _securityRandomContext = RegExp(
    r'token|\bkey\b|salt|nonce|\biv\b|\botp\b|randomBytes|secret|credential',
    caseSensitive: false,
  );

  static final RegExp _uiRandomContext = RegExp(
    r'uiKey|animation|Color|Offset|widget|build\s*\(|GlobalKey|nextInt\s*\(\s*\d{1,4}\s*\)',
    caseSensitive: false,
  );

  /// Skip test/mock/example lines and obvious placeholder secrets.
  static bool isTestMockLine(String line) {
    if (_mockToken.hasMatch(line)) {
      return true;
    }
    if (_mockValueLiteral.hasMatch(line)) {
      return true;
    }
    if (RegExp(
      r'test_key|example_token|mock_secret',
      caseSensitive: false,
    ).hasMatch(line)) {
      return true;
    }
    return false;
  }

  static bool isPlaceholderSecretValue(String value) {
    final String v = value.toLowerCase();
    if (v.length < 12) {
      return true;
    }
    return RegExp(
      r'^(?:test|mock|example|sample|demo|placeholder|fake)[_a-z0-9]*$',
      caseSensitive: false,
    ).hasMatch(v);
  }

  static LineContextKind classify(String line) {
    if (isTestMockLine(line)) {
      return LineContextKind.testMock;
    }
    if (_logCall.hasMatch(line)) {
      return LineContextKind.logging;
    }
    if (_prefsWrite.hasMatch(line)) {
      return LineContextKind.storage;
    }
    if (RegExp(r'http://|https://|HttpClient|Dio\b').hasMatch(line)) {
      return LineContextKind.network;
    }
    if (_uiLabel.hasMatch(line) || _uiScreenPhrase.hasMatch(line)) {
      return LineContextKind.uiString;
    }
    if (RegExp(
      r'apiKey|firebase|FirebaseOptions|config\s*[:=]',
      caseSensitive: false,
    ).hasMatch(line)) {
      return LineContextKind.config;
    }
    return LineContextKind.general;
  }

  static bool isUiStringLine(String line) =>
      classify(line) == LineContextKind.uiString;

  /// SharedPreferences write with a genuinely sensitive key name.
  static bool isSensitivePrefsWrite(String line) {
    if (!_prefsWrite.hasMatch(line)) {
      return false;
    }
    final RegExpMatch? keyMatch = RegExp(
      r'''\.(?:setString|setInt|setBool)\s*\(\s*([^,)]+)''',
    ).firstMatch(line);
    final String key = (keyMatch?.group(1) ?? line).toLowerCase();
    if (prefsBenignKey.hasMatch(key)) {
      return false;
    }
    if (RegExp(
      r'(?:token|auth|password|secret).*(?:screen|hint|button|opened|clicked|seen)',
      caseSensitive: false,
    ).hasMatch(key)) {
      return false;
    }
    return prefsHighRiskKey.hasMatch(key);
  }

  /// Logs that interpolate credential *values*, not metadata like `.length`.
  static bool logsSensitiveValue(String line) {
    if (!_logCall.hasMatch(line)) {
      return false;
    }
    if (!line.contains(r'$')) {
      return false;
    }
    if (RegExp(
      r'\$\{?\s*\w+\.(length|hashCode|isEmpty|isNotEmpty|runtimeType|toString)',
    ).hasMatch(line)) {
      return false;
    }
    if (RegExp(
      r'(?:print|debugPrint|log)\s*\(\s*(?:token|password|secret|credential|apiKey|authToken)\w*\s*\)',
      caseSensitive: false,
    ).hasMatch(line)) {
      return true;
    }
    if (RegExp(
      r'''\$\{?\w*(?:token|password|secret|credential|apikey|authtoken)''',
      caseSensitive: false,
    ).hasMatch(line)) {
      return true;
    }
    if (RegExp(
      r'''["'][^"']*\$\{?\w*(?:token|password|secret|credential)''',
      caseSensitive: false,
    ).hasMatch(line)) {
      return true;
    }
    return false;
  }

  static bool isSecurityRandomContext(String line, List<String> window) {
    if (_uiRandomContext.hasMatch(line) &&
        !_securityRandomContext.hasMatch(line)) {
      return false;
    }
    final String context = window.join('\n');
    return _securityRandomContext.hasMatch(context);
  }

  /// Dev/staging hosts that should not be flagged as cleartext production HTTP.
  static bool isDevOrLocalHost(String host) {
    final String h = (host.contains(':') ? host.split(':').first : host)
        .toLowerCase();
    if (h == 'localhost' || h == '127.0.0.1' || h == '::1') {
      return true;
    }
    if (h.endsWith('.local') || h.endsWith('.internal')) {
      return true;
    }
    if (h.startsWith('dev.') ||
        h.startsWith('staging.') ||
        h.contains('.dev.') ||
        h.contains('.staging.')) {
      return true;
    }
    if (h.startsWith('10.') || h.startsWith('192.168.') || h.startsWith('172.')) {
      return true;
    }
    return false;
  }
}
