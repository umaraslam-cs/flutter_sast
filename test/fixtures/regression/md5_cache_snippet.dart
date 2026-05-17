// T05 — MD5 cache path must not trigger DART-005b (or LOW MD5 only)
import 'dart:io';

void cacheVideo(String rootPath, String url) {
  final localFileName = md5(url);
  File('$rootPath/cached-videos/$localFileName.mp4');
}

String md5(String input) => input.hashCode.toRadixString(16);
