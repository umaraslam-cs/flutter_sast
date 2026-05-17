// T06 — badCertificateCallback with validateCertificate → not CRITICAL
import 'dart:io';

class DioWrapper {
  void setup() {
    final HttpClient client = HttpClient();
    client.badCertificateCallback = (cert, host, port) {
      return true;
    };
    // ignore: unused_local_variable
    bool validateCertificate(Object cert, String host, int port) {
      final fingerprint = sha256(cert);
      return fingerprint == expected;
    }
  }
}

String sha256(Object cert) => '';
String get expected => '';
