@Tags(['kdbx3'])
import 'dart:io';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/protected_salt_generator.dart';
import 'package:logging/logging.dart';
import 'package:synchronized/synchronized.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

final _logger = Logger('kdbx_test');

class FakeProtectedSaltGenerator implements ProtectedSaltGenerator {
  @override
  String decryptBase64(String protectedValue) => 'fake';

  @override
  String encryptToBase64(String plainValue) => 'fake';
}

void main() {
  final testUtil = TestUtil();
  final kdbxFormat = testUtil.kdbxFormat;
  group('Reading', () {
    setUp(() {});

    test('First Test', () async {
      final data = await File('test/FooBar.kdbx').readAsBytes();
      await kdbxFormat.read(
          data, Credentials(ProtectedValue.fromString('FooBar')));
    });
  });

  group('Composite key', () {
    Future<KdbxFile> readFile(
        String kdbxFile, String password, String keyFile) async {
      final keyFileBytes = await File(keyFile).readAsBytes();
      final cred = Credentials.composite(
          ProtectedValue.fromString(password), keyFileBytes);
      final data = await File(kdbxFile).readAsBytes();
      return await kdbxFormat.read(data, cred);
    }

    test('Read with PW and keyfile', () async {
      final keyFileBytes =
          await File('test/password-and-keyfile.key').readAsBytes();
      final cred = Credentials.composite(
          ProtectedValue.fromString('asdf'), keyFileBytes);
      final data = await File('test/password-and-keyfile.kdbx').readAsBytes();
      final file = await kdbxFormat.read(data, cred);
      expect(file.body.rootGroup.entries, hasLength(2));
    });
    test('Read with PW and hex keyfile', () async {
      final file = await readFile('test/keyfile/newdatabase2.kdbx', 'testing99',
          'test/keyfile/hexkey_no_newline');
      expect(file.body.rootGroup.entries, hasLength(3));
    });
    test('Keyfile v2 with PW and keyfile', () async {
      final file = await readFile(
          'test/keyfile/keyfilev2.kdbx', 'qwe', 'test/keyfile/keyfilev2.keyx');
      expect(file.body.rootGroup.entries, hasLength(2));
    });
  });

  group('Creating', () {
    test('Simple create', () {
      final kdbx = kdbxFormat.create(
          Credentials(ProtectedValue.fromString('FooBar')), 'CreateTest');
      expect(kdbx, isNotNull);
      expect(kdbx.body.rootGroup, isNotNull);
      expect(kdbx.body.rootGroup.name.get(), 'CreateTest');
      expect(kdbx.body.meta.databaseName.get(), 'CreateTest');
      print(kdbx.body
          .generateXml(FakeProtectedSaltGenerator())
          .toXmlString(pretty: true));
    });
    test('Create Entry', () {
      final kdbx = kdbxFormat.create(
          Credentials(ProtectedValue.fromString('FooBar')), 'CreateTest');
      final rootGroup = kdbx.body.rootGroup;
      final entry = KdbxEntry.create(kdbx, rootGroup);
      rootGroup.addEntry(entry);
      entry.setString(
          KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('LoremIpsum'));
      print(kdbx.body
          .generateXml(FakeProtectedSaltGenerator())
          .toXmlString(pretty: true));
    });
  });

  group('times', () {
    test('read mod date time', () async {
      final file = await testUtil.readKdbxFile('test/keepass2test.kdbx');
      final first = file.body.rootGroup.entries.first;
      expect(file.header.version.major, 3);
      expect(first.getString(KdbxKeyCommon.TITLE)!.getText(), 'Sample Entry');
      final modTime = first.times.lastModificationTime.get();
      expect(modTime, DateTime.utc(2020, 5, 6, 7, 31, 48));
    });
    test('update mod date time', () async {
      final newModDate = DateTime.utc(2020, 1, 2, 3, 4, 5);
      final file = await testUtil.readKdbxFile('test/keepass2test.kdbx');
      {
        final first = file.body.rootGroup.entries.first;
        expect(file.header.version.major, 3);
        expect(first.getString(KdbxKeyCommon.TITLE)!.getText(), 'Sample Entry');
        first.times.lastModificationTime.set(newModDate);
      }
      final saved = await file.save();
      {
        final file = await testUtil.readKdbxFileBytes(saved);
        final first = file.body.rootGroup.entries.first;
        final modTime = first.times.lastModificationTime.get();
        expect(modTime, newModDate);
      }
    });
  });

  group('Integration', () {
    test('Simple save and load', () async {
      final credentials = Credentials(ProtectedValue.fromString('FooBar'));
      final saved = await (() async {
        final kdbx = kdbxFormat.create(credentials, 'CreateTest');
        final rootGroup = kdbx.body.rootGroup;
        final entry = KdbxEntry.create(kdbx, rootGroup);
        rootGroup.addEntry(entry);
        entry.setString(
            KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('LoremIpsum'));
        return kdbx.save();
      })();

//      print(ByteUtils.toHexList(saved));

      final kdbx = await kdbxFormat.read(saved, credentials);
      expect(
          kdbx.body.rootGroup.entries.first
              .getString(KdbxKeyCommon.PASSWORD)!
              .getText(),
          'LoremIpsum');
      File('test.kdbx').writeAsBytesSync(saved);
    });
    test('concurrent save test', () async {
      final file = await testUtil.readKdbxFile('test/keepass2test.kdbx');
      final readLock = Lock();
      Future<KdbxFile> doSave(
          Future<Uint8List> byteFuture, String debug) async {
        _logger.fine('$debug: Waiting...');
        final bytes = await byteFuture;
        return await readLock.synchronized(() {
          try {
            final ret = testUtil.readKdbxFileBytes(bytes);
            _logger.fine('$debug FINISHED: success');
            return ret;
          } catch (e, stackTrace) {
            _logger.shout(
                '$debug FINISHED: error while reading file', e, stackTrace);
            rethrow;
          }
        });
      }

      final save1 = doSave(file.save(), 'first ');
      final save2 = doSave(file.save(), 'second');
      expect((await save1).body.meta.databaseName.get(), isNotNull);
      expect((await save2).body.meta.databaseName.get(), isNotNull);
    });
  });
}
