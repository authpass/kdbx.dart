import 'dart:ffi';
import 'dart:io';

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
      final data = await File('test/keepassxcpasswords.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      final firstEntry = file.body.rootGroup.entries.first;
      final pwd = firstEntry.getString(KdbxKey('Password')).getText();
      expect(pwd, 'MyPassword');
    });
    test('Reading kdbx4_keeweb', () async {
      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      final firstEntry = file.body.rootGroup.entries.first;
      final pwd = firstEntry.getString(KdbxKey('Password')).getText();
      expect(pwd, 'def');
    });
    test('Binary Keyfile', () async {
      final data =
          await File('test/keyfile/BinaryKeyFilePasswords.kdbx').readAsBytes();
      final keyFile =
          await File('test/keyfile/binarykeyfile.key').readAsBytes();
      final file = await kdbxFormat.read(data,
          Credentials.composite(ProtectedValue.fromString('asdf'), keyFile));
      expect(file.body.rootGroup.entries, hasLength(1));
    });
    test('Reading chacha20', () async {
      final data = await File('test/chacha20.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      expect(file.body.rootGroup.entries, hasLength(1));
    });
    test('Reading aes-kdf', () async {
      final data = await File('test/aeskdf.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      expect(file.body.rootGroup.entries, hasLength(1));
    }, skip: 'Takes tooo long, too many iterations.');
  });
  group('Writing', () {
    test('Create and save', () async {
      final credentials = Credentials(ProtectedValue.fromString('asdf'));
      final kdbx = kdbxFormat.create(
        credentials,
        'Test Keystore',
        header: KdbxHeader.createV4(),
      );
      final rootGroup = kdbx.body.rootGroup;
      _createEntry(kdbx, rootGroup, 'user1', 'LoremIpsum');
      _createEntry(kdbx, rootGroup, 'user2', 'Second Password');
      final saved = await kdbx.save();

      final loadedKdbx = await kdbxFormat.read(
          saved, Credentials(ProtectedValue.fromString('asdf')));
      _logger.fine('Successfully loaded kdbx $loadedKdbx');
      File('test_v4x.kdbx').writeAsBytesSync(saved);
    });
    test('Reading it', () async {
      final data = await File('test/test_v4x.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      _logger.fine('successfully read  ${file.body.rootGroup.name}');
    });
    test('write chacha20', () async {
      final data = await File('test/chacha20.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      expect(file.body.rootGroup.entries, hasLength(1));
      _createEntry(file, file.body.rootGroup, 'user1', 'LoremIpsum');

      // and try to write it.
      final output = await file.save();
      expect(output, isNotNull);
      File('test_output_chacha20.kdbx').writeAsBytesSync(output);
    });
  });
}

KdbxEntry _createEntry(
    KdbxFile file, KdbxGroup group, String username, String password) {
  final entry = KdbxEntry.create(file, group);
  group.addEntry(entry);
  entry.setString(KdbxKey('UserName'), PlainValue(username));
  entry.setString(KdbxKey('Password'), ProtectedValue.fromString(password));
  return entry;
}
