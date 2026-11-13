import 'dart:io';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_header.dart';

import 'package:logging/logging.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

final _logger = Logger('kdbx4_test_pointycastle');

void main() {
  // ignore: unused_local_variable
  final testUtil = TestUtil();
  final kdbxFormat = KdbxFormat();
  if (kdbxFormat.argon2.isFfi) {
    throw StateError('Expected non-ffi implementation.');
  }
  _logger.fine('argon2 implementation: ${kdbxFormat.argon2}');
  group('Reading pointycastle argon2', () {
    test('pc: Reading kdbx4_keeweb', () async {
      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      final firstEntry = file.body.rootGroup.entries.first;
      final pwd = firstEntry.getString(KdbxKeyCommon.PASSWORD)!.getText();
      expect(pwd, 'def');
    });
  });
  group('Writing pointycastle argon2', () {
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
  });
}

KdbxEntry _createEntry(
    KdbxFile file, KdbxGroup group, String username, String password) {
  final entry = KdbxEntry.create(file, group);
  group.addEntry(entry);
  entry.setString(KdbxKeyCommon.USER_NAME, PlainValue(username));
  entry.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(password));
  return entry;
}
