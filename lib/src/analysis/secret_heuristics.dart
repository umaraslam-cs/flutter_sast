// lib/src/analysis/secret_heuristics.dart

/// Heuristics for distinguishing real secrets from i18n keys, storage keys, etc.
abstract final class SecretHeuristics {
  static final RegExp _snakeCaseKey = RegExp(r'^[a-z][a-z0-9_]*$');
  static final RegExp _localeConstLine = RegExp(
    r"^\s*static\s+const\s+(\w+)\s*=\s*'([^']+)'\s*;?\s*$",
  );
  static final RegExp _storageKeyDef = RegExp(
    r"^\s*(?:static\s+)?(?:final|const)\s+[_\w]*(?:token|password|secret|key)"
    r"[_\w]*\s*=\s*'([^']+)'\s*;?\s*$",
    caseSensitive: false,
  );
  static final RegExp _assignmentSecretName = RegExp(
    r'\b(?:String\s+)?(?:password|clientSecret|apiSecret|privateKey|clientId)\s*=',
    caseSensitive: false,
  );
  static final RegExp _jwtShape = RegExp(
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
  );

  static bool isGeneratedDartPath(String filePath) {
    final String p = filePath.replaceAll('\\', '/');
    return p.endsWith('.g.dart') ||
        p.contains('/generated/') ||
        p.endsWith('locales.g.dart');
  }

  static bool isDemoOrSamplePath(String filePath) {
    final String p = filePath.replaceAll('\\', '/');
    return p.contains('/example/') ||
        p.contains('/samples/') && p.endsWith('/data.dart') ||
        p.contains('/demo/') ||
        p.contains('_example');
  }

  /// `static const password = 'password';` — i18n key, not a credential.
  static bool isLocaleI18nConstantLine(String line) {
    final RegExpMatch? m = _localeConstLine.firstMatch(line.trim());
    if (m == null) {
      return false;
    }
    final String name = m.group(1)!;
    final String value = m.group(2)!;
    if (value == name) {
      return true;
    }
    final String normName = name.replaceAll('_', '').toLowerCase();
    final String normValue = value.replaceAll('_', '').toLowerCase();
    if (_snakeCaseKey.hasMatch(value) &&
        (normName.contains(normValue) || normValue == normName)) {
      return true;
    }
    if (_snakeCaseKey.hasMatch(value) && value.length < 40) {
      final String lowerName = name.toLowerCase();
      if (lowerName.contains('password') ||
          lowerName.contains('token') ||
          lowerName.contains('error') ||
          lowerName.contains('hint') ||
          lowerName.contains('label')) {
        return true;
      }
    }
    return false;
  }

  /// `final _registrationRefreshToken = 'registration_refresh_token';`
  static bool isStorageKeyDefinitionLine(String line) {
    final RegExpMatch? m = _storageKeyDef.firstMatch(line.trim());
    if (m == null) {
      return false;
    }
    final String value = m.group(1)!;
    if (!_snakeCaseKey.hasMatch(value)) {
      return false;
    }
    if (value.startsWith('Bearer ') || _jwtShape.hasMatch(value)) {
      return false;
    }
    return true;
  }

  static bool isSnakeCaseIdentifierString(String value) {
    return _snakeCaseKey.hasMatch(value.trim());
  }

  static bool looksLikeSecretValue(String value) {
    final String v = value.trim();
    if (v.isEmpty) {
      return false;
    }
    if (v.startsWith('Bearer ') || _jwtShape.hasMatch(v)) {
      return true;
    }
    if (RegExp(r'^sk_live_|^GOCSPX-|^AKIA[0-9A-Z]{16}').hasMatch(v)) {
      return true;
    }
    return hasHighEntropy(v);
  }

  /// Mixed charset + length threshold for credential literals.
  static bool hasHighEntropy(String value, {int minLength = 12}) {
    if (value.length < minLength) {
      return false;
    }
    var hasLower = false;
    var hasUpper = false;
    var hasDigit = false;
    var hasSymbol = false;
    for (final int code in value.codeUnits) {
      if (code >= 0x61 && code <= 0x7a) {
        hasLower = true;
      } else if (code >= 0x41 && code <= 0x5a) {
        hasUpper = true;
      } else if (code >= 0x30 && code <= 0x39) {
        hasDigit = true;
      } else {
        hasSymbol = true;
      }
    }
    final int kinds =
        (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
    return kinds >= 2;
  }

  static bool isHardcodedCredentialAssignment(String line) {
    if (!_assignmentSecretName.hasMatch(line)) {
      return false;
    }
    final RegExpMatch? valueMatch = RegExp(
      r'''=\s*["']([^"']+)["']''',
    ).firstMatch(line);
    final String? value = valueMatch?.group(1);
    if (value == null) {
      return false;
    }
    if (isSnakeCaseIdentifierString(value) && value.length < 32) {
      return false;
    }
    return looksLikeSecretValue(value) || value.length >= 12 && hasHighEntropy(value);
  }

  static bool isMd5CacheContext(String line, List<String> window) {
    final String ctx = '$line\n${window.join('\n')}';
    return RegExp(
      r'\b(?:cache|cached|cached-videos|localFileName|fileName|hashCode)\b|'
      r'md5\s*\([^)]*(?:url|path|key)',
      caseSensitive: false,
    ).hasMatch(ctx);
  }

  static bool isSecurityCryptoContext(String line, List<String> window) {
    final String ctx = '$line\n${window.join('\n')}';
    return RegExp(
      r'\b(?:password|Hmac|sign|encrypt|bcrypt|auth|credential|secret|token)\b',
      caseSensitive: false,
    ).hasMatch(ctx);
  }

  /// SHA-1 used for display, certs, or identifiers — not a security primitive.
  static bool isSha1BenignContext(String line, List<String> window) {
    final String ctx = '$line\n${window.join('\n')}';
    return RegExp(
      r'\b(?:thumbprint|fingerprint|certificate|cert|changelog|git|display|'
      r'format|etag|identifier|avatar|url)\b',
      caseSensitive: false,
    ).hasMatch(ctx);
  }
}
