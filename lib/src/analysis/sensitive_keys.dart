// lib/src/analysis/sensitive_keys.dart

/// Query-param keys, exception interpolation, and related sensitive identifiers.
abstract final class SensitiveKeys {
  static final RegExp queryParamKey = RegExp(
    r'''['"]?(?:token|password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|'''
    r'''refresh[_-]?token|access[_-]?token|bearer|credential|private[_-]?key|'''
    r'''session[_-]?id|otp|pin)['"]?\s*[:=]''',
    caseSensitive: false,
  );

  static final RegExp urlQuerySensitive = RegExp(
    r'[?&](?:token|password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|'
    r'refresh[_-]?token|access[_-]?token|session[_-]?id|otp|pin)=',
    caseSensitive: false,
  );

  static final RegExp interpolatedSensitive = RegExp(
    r'\$\{?\w*(?:token|password|passwd|pwd|secret|apikey|api_key|authToken|'
    r'credential|refreshToken|accessToken|sessionId|otp|pin)\w*\}?',
    caseSensitive: false,
  );
}
