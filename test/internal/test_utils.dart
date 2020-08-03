//typedef HashStuff = Pointer<Utf8> Function(Pointer<Utf8> str);
import 'dart:io';
import 'dart:typed_data';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:kdbx/kdbx.dart';

// ignore_for_file: non_constant_identifier_names

import 'package:logging/logging.dart';

final _logger = Logger('test_utils');

class TestUtil {
  static KdbxFormat kdbxFormat() {
    Argon2.resolveLibraryForceDynamic = true;
    return KdbxFormat(Argon2FfiFlutter(resolveLibrary: (path) {
      final cwd = Directory('.').absolute.uri;
      final p = cwd.resolve(path);
      final filePath = p.toFilePath();
      _logger.fine('Resolving $path to: $filePath (${Platform.script})');
      return filePath;
    }));
  }

  static Future<KdbxFile> readKdbxFile(
    String filePath, {
    String password = 'asdf',
  }) async {
    final kdbxFormat = TestUtil.kdbxFormat();
    final data = await File(filePath).readAsBytes();
    final file = await kdbxFormat.read(
        data, Credentials(ProtectedValue.fromString(password)));
    return file;
  }

  static Future<KdbxFile> readKdbxFileBytes(Uint8List data,
      {String password = 'asdf'}) async {
    final kdbxFormat = TestUtil.kdbxFormat();
    final file = await kdbxFormat.read(
        data, Credentials(ProtectedValue.fromString(password)));
    return file;
  }
}
