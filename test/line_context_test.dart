import 'package:flutter_sast/src/analysis/line_context.dart';
import 'package:test/test.dart';

void main() {
  group('LineContext', () {
    test('skips test/mock placeholder secrets', () {
      expect(
        LineContext.isTestMockLine('final apiKey = "test_key_123";'),
        isTrue,
      );
    });

    test('skips UI label lines', () {
      expect(
        LineContext.isUiStringLine('hintText: "Enter password",'),
        isTrue,
      );
    });

    test('prefs: ignores token screen metadata keys', () {
      expect(
        LineContext.isSensitivePrefsWrite(
          'prefs.setString("last_token_screen_opened", "true");',
        ),
        isFalse,
      );
    });

    test('prefs: flags access token keys', () {
      expect(
        LineContext.isSensitivePrefsWrite(
          'await prefs.setString("access_token", token);',
        ),
        isTrue,
      );
    });

    test('logs: ignores static password message', () {
      expect(
        LineContext.logsSensitiveValue(
          "print('Error: update password attempted');",
        ),
        isFalse,
      );
    });

    test('logs: ignores token.length metadata', () {
      expect(
        LineContext.logsSensitiveValue(
          'debugPrint("token length: \${token.length}");',
        ),
        isFalse,
      );
    });

    test('logs: flags interpolated token value', () {
      expect(
        LineContext.logsSensitiveValue("print('auth: \$userToken');"),
        isTrue,
      );
    });

    test('isDevOrLocalHost includes staging and internal', () {
      expect(LineContext.isDevOrLocalHost('dev.api.example'), isTrue);
      expect(LineContext.isDevOrLocalHost('api.staging.example'), isTrue);
      expect(LineContext.isDevOrLocalHost('api.production.example'), isFalse);
    });

    test('isRoutePathValue recognises slash routes', () {
      expect(LineContext.isRoutePathValue('/edit-password'), isTrue);
      expect(LineContext.isRoutePathValue('sup3rs3cret123'), isFalse);
    });

    test('isSafeLocalFilePathLine allows tempDir + K constant', () {
      expect(
        LineContext.isSafeLocalFilePathLine(
          "final File logFile = File('\${tempDir.path}/\${K.logFilename}');",
        ),
        isTrue,
      );
    });
  });
}
