// T09 — default AndroidOptions must not trigger DART-018

class FlutterSecureStorage {
  const FlutterSecureStorage({this.aOptions});
  final AndroidOptions? aOptions;
}

class AndroidOptions {
  const AndroidOptions();
}

final storage = const FlutterSecureStorage(
  aOptions: AndroidOptions(),
);
