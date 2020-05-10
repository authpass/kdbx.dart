//typedef HashStuff = Pointer<Utf8> Function(Pointer<Utf8> str);
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:kdbx/kdbx.dart';

// ignore_for_file: non_constant_identifier_names

typedef Argon2HashNative = Pointer<Utf8> Function(
  Pointer<Uint8> key,
  IntPtr keyLen,
  Pointer<Uint8> salt,
  Uint64 saltlen,
  Uint32 m_cost, // memory cost
  Uint32 t_cost, // time cost (number iterations)
  Uint32 parallelism,
  IntPtr hashlen,
  Uint8 type,
  Uint32 version,
);
typedef Argon2Hash = Pointer<Utf8> Function(
  Pointer<Uint8> key,
  int keyLen,
  Pointer<Uint8> salt,
  int saltlen,
  int m_cost, // memory cost
  int t_cost, // time cost (number iterations)
  int parallelism,
  int hashlen,
  int type,
  int version,
);

class Argon2Test extends Argon2Base {
  Argon2Test() {
    final argon2lib = Platform.isMacOS
        ? DynamicLibrary.open('libargon2_ffi.dylib')
        : DynamicLibrary.open('./libargon2_ffi.so');
    argon2hash = argon2lib
        .lookup<NativeFunction<Argon2HashNative>>('hp_argon2_hash')
        .asFunction();
  }

  @override
  Argon2Hash argon2hash;
}

class TestUtil {
  static Future<KdbxFile> readKdbxFile(
    String filePath, {
    String password = 'asdf',
  }) async {
    final kdbxFormat = KdbxFormat(Argon2Test());
    final data = await File(filePath).readAsBytes();
    final file = await kdbxFormat.read(
        data, Credentials(ProtectedValue.fromString(password)));
    return file;
  }

  static Future<KdbxFile> readKdbxFileBytes(Uint8List data,
      {String password = 'asdf'}) async {
    final kdbxFormat = KdbxFormat(Argon2Test());
    final file = await kdbxFormat.read(
        data, Credentials(ProtectedValue.fromString(password)));
    return file;
  }
}
