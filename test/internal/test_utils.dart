//typedef HashStuff = Pointer<Utf8> Function(Pointer<Utf8> str);
import 'dart:io';
import 'dart:typed_data';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:kdbx/kdbx.dart';

// ignore_for_file: non_constant_identifier_names

class TestUtil {
  static Future<KdbxFile> readKdbxFile(
    String filePath, {
    String password = 'asdf',
  }) async {
    final kdbxFormat = KdbxFormat(Argon2FfiFlutter());
    final data = await File(filePath).readAsBytes();
    final file = await kdbxFormat.read(
        data, Credentials(ProtectedValue.fromString(password)));
    return file;
  }

  static Future<KdbxFile> readKdbxFileBytes(Uint8List data,
      {String password = 'asdf'}) async {
    final kdbxFormat = KdbxFormat(Argon2FfiFlutter());
    final file = await kdbxFormat.read(
        data, Credentials(ProtectedValue.fromString(password)));
    return file;
  }
}
