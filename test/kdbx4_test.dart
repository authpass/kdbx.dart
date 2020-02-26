import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

final _logger = Logger('kdbx4_test');

// ignore_for_file: non_constant_identifier_names

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

void main() {
  Logger.root.level = Level.ALL;
  PrintAppender().attachToLogger(Logger.root);
  final kdbxFormat = KdbxFormat(Argon2Test());
  group('Reading', () {
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
    test('Reading kdbx4_keeweb', () async {
      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      final file =
          kdbxFormat.read(data, Credentials(ProtectedValue.fromString('asdf')));
      final firstEntry = file.body.rootGroup.entries.first;
      final pwd = firstEntry.getString(KdbxKey('Password')).getText();
      expect(pwd, 'def');
    });
  });
  group('Writing', () {
    test('Create and save', () {
      final credentials = Credentials(ProtectedValue.fromString('asdf'));
      final kdbx = kdbxFormat.create(
        credentials,
        'Test Keystore',
        header: KdbxHeader.createV4(),
      );
      final rootGroup = kdbx.body.rootGroup;
      {
        final entry = KdbxEntry.create(kdbx, rootGroup);
        rootGroup.addEntry(entry);
        entry.setString(KdbxKey('Username'), PlainValue('user1'));
        entry.setString(
            KdbxKey('Password'), ProtectedValue.fromString('LoremIpsum'));
      }
      {
        final entry = KdbxEntry.create(kdbx, rootGroup);
        rootGroup.addEntry(entry);
        entry.setString(KdbxKey('Username'), PlainValue('user2'));
        entry.setString(
          KdbxKey('Password'),
          ProtectedValue.fromString('Second Password'),
        );
      }
      final saved = kdbx.save();

      final loadedKdbx = kdbxFormat.read(
          saved, Credentials(ProtectedValue.fromString('asdf')));
      _logger.fine('Successfully loaded kdbx $loadedKdbx');
      File('test_v4x.kdbx').writeAsBytesSync(saved);
    });
    test('Reading it', () async {
      final data = await File('test/test_v4x.kdbx').readAsBytes();
      final file =
          kdbxFormat.read(data, Credentials(ProtectedValue.fromString('asdf')));
    });
  });
}
