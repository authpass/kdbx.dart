import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:ffi_helper/ffi_helper.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/key_encrypter_kdf.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

final _logger = Logger('kdbx4_test');

//typedef HashStuff = Pointer<Utf8> Function(Pointer<Utf8> str);
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

class Argon2Test implements Argon2 {
  Argon2Test() {
//    final argon2lib = DynamicLibrary.open('libargon2.1.dylib');
    final argon2lib = DynamicLibrary.open('libargon2_ffi.dylib');
    _argon2hash = argon2lib
        .lookup<NativeFunction<Argon2HashNative>>('hp_argon2_hash')
        .asFunction();
  }
  Argon2Hash _argon2hash;

  @override
  Uint8List argon2(
    Uint8List key,
    Uint8List salt,
    int memory,
    int iterations,
    int length,
    int parallelism,
    int type,
    int version,
  ) {
//    print('hash: ${hashStuff('abc')}');
    final keyArray = Uint8Array.fromTypedList(key);
//    final saltArray = Uint8Array.fromTypedList(salt);
    final saltArray = allocate<Uint8>(count: salt.length);
    final saltList = saltArray.asTypedList(length);
    saltList.setAll(0, salt);
    const int memoryCost = 1 << 16;

//    _logger.fine('saltArray: ${ByteUtils.toHexList(saltArray.view)}');

    final result = _argon2hash(
      keyArray.rawPtr,
      keyArray.length,
      saltArray,
      salt.length,
      memoryCost,
      iterations,
      parallelism,
      length,
      type,
      version,
    );

    keyArray.free();
//    saltArray.free();
    free(saltArray);
    final resultString = Utf8.fromUtf8(result);
    return base64.decode(resultString);
  }

//  String hashStuff(String password) =>
//      Utf8.fromUtf8(_hashStuff(Utf8.toUtf8(password)));
}

void main() {
  Logger.root.level = Level.ALL;
  PrintAppender().attachToLogger(Logger.root);
  final kdbxFormat = KdbxFormat(Argon2Test());
  group('Reading', () {
    final argon2 = Argon2Test();
    test('bubb', () async {
      final key = utf8.encode('asdf') as Uint8List;
      final salt = Uint8List(8);
//      final result = Argon2Test().argon2(key, salt, 1 << 16, 5, 16, 1, 0x13, 1);
//      _logger.fine('hashing: $result');
      final data = await File('test/keepassxcpasswords.kdbx').readAsBytes();
      final file =
          kdbxFormat.read(data, Credentials(ProtectedValue.fromString('asdf')));
      final firstEntry = file.body.rootGroup.entries.first;
      final pwd = firstEntry.getString(KdbxKey('Password')).getText();
      expect(pwd, 'MyPassword');
    });
  });
  group('Writing', () {
    test('Create and save', () {
      final credentials = Credentials(ProtectedValue.fromString('asdf'));
      final kdbx = kdbxFormat.create(credentials, 'Test Keystore');
      final rootGroup = kdbx.body.rootGroup;
      final entry = KdbxEntry.create(kdbx, rootGroup);
      rootGroup.addEntry(entry);
      entry.setString(
          KdbxKey('Password'), ProtectedValue.fromString('LoremIpsum'));
      final saved = kdbx.save();

      final loadedKdbx = kdbxFormat.read(saved, credentials);
      File('test_v4.kdbx').writeAsBytesSync(saved);
    });
  });
}
