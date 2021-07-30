@Tags(['kdbx4'])
import 'dart:io';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

final _logger = Logger('kdbx4_test');

// ignore_for_file: non_constant_identifier_names

void main() {
  final testUtil = TestUtil();
  final kdbxFormat = testUtil.kdbxFormat;
  group('Reading', () {
    test('bubb', () async {
      final data = await File('test/keepassxcpasswords.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      final firstEntry = file.body.rootGroup.entries.first;
      final pwd = firstEntry.getString(KdbxKeyCommon.PASSWORD)!.getText();
      expect(pwd, 'MyPassword');
    });
    test('Reading kdbx4_keeweb', () async {
      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      final file = await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('asdf')));
      final firstEntry = file.body.rootGroup.entries.first;
      final pwd = firstEntry.getString(KdbxKeyCommon.PASSWORD)!.getText();
      expect(pwd, 'def');
    });
    test('Reading kdbx4_keeweb modification time', () async {
      final file = await testUtil.readKdbxFile('test/kdbx4_keeweb.kdbx');
      final firstEntry = file.body.rootGroup.entries.first;
      final createTime = firstEntry.times.creationTime.get();
      expect(createTime, DateTime.utc(2020, 2, 26, 13, 40, 48));
      final modTime = firstEntry.times.lastModificationTime.get();
      expect(modTime, DateTime.utc(2020, 2, 26, 13, 40, 54));
    });
    test('Change kdbx4 modification time', () async {
      final file = await testUtil.readKdbxFile('test/kdbx4_keeweb.kdbx');
      final firstEntry = file.body.rootGroup.entries.first;
      final d = DateTime.utc(2020, 4, 5, 10, 0);
      firstEntry.times.lastModificationTime.set(d);
      final saved = await file.save();
      {
        final file2 = await testUtil.readKdbxFileBytes(saved);
        final firstEntry = file2.body.rootGroup.entries.first;
        expect(firstEntry.times.lastModificationTime.get(), d);
      }
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
  group('recycle bin test', () {
    test('empty recycle bin with "zero" uuid', () async {
      final file = await testUtil.readKdbxFile('test/keepass2test.kdbx');
      final recycleBin = file.recycleBin;
      expect(recycleBin, isNull);
    });
    test('check deleting item', () async {
      final file = await testUtil.readKdbxFile('test/keepass2test.kdbx');
      expect(file.recycleBin, isNull);
      final entry = file.body.rootGroup.getAllEntries().first;
      file.deleteEntry(entry);
      expect(file.recycleBin, isNotNull);
      expect(entry.parent, equals(file.recycleBin));
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
