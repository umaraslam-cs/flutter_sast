// T04 — toString must not trigger DART-005b
class FileUploadNotification {
  @override
  String toString() => 'File(key=$key, value=${(value as _V).raw})';
  Object get key => '';
  Object get value => _V();
}

class _V {
  String get raw => '';
}
