import 'dart:io';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/protected_salt_generator.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

class FakeProtectedSaltGenerator implements ProtectedSaltGenerator {
  @override
  String decryptBase64(String protectedValue) => 'fake';

  @override
  String encryptToBase64(String plainValue) => 'fake';
}

void main() {
  Logger.root.level = Level.ALL;
  PrintAppender().attachToLogger(Logger.root);
  final kdbxForamt = KdbxFormat();
  group('Reading', () {
    setUp(() {});

    test('First Test', () async {
      final data = await File('test/FooBar.kdbx').readAsBytes();
      await kdbxForamt.read(
          data, Credentials(ProtectedValue.fromString('FooBar')));
    });
  });

  group('Composite key', () {
    test('Read with PW and keyfile', () async {
      final keyFileBytes =
          await File('test/password-and-keyfile.key').readAsBytes();
      final cred = Credentials.composite(
          ProtectedValue.fromString('asdf'), keyFileBytes);
      final data = await File('test/password-and-keyfile.kdbx').readAsBytes();
      final file = await kdbxForamt.read(data, cred);
      expect(file.body.rootGroup.entries, hasLength(2));
    });
    test('Read with PW and hex keyfile', () async {
      final keyFileBytes =
          await File('test/keyfile/hexkey_no_newline').readAsBytes();
      final cred = Credentials.composite(
          ProtectedValue.fromString('testing99'), keyFileBytes);
      final data = await File('test/keyfile/newdatabase2.kdbx').readAsBytes();
      final file = await kdbxForamt.read(data, cred);
      expect(file.body.rootGroup.entries, hasLength(3));
    });
  });

  group('Creating', () {
    test('Simple create', () {
      final kdbx = kdbxForamt.create(
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
      final kdbx = kdbxForamt.create(
          Credentials(ProtectedValue.fromString('FooBar')), 'CreateTest');
      final rootGroup = kdbx.body.rootGroup;
      final entry = KdbxEntry.create(kdbx, rootGroup);
      rootGroup.addEntry(entry);
      entry.setString(
          KdbxKey('Password'), ProtectedValue.fromString('LoremIpsum'));
      print(kdbx.body
          .generateXml(FakeProtectedSaltGenerator())
          .toXmlString(pretty: true));
    });
  });

  group('Integration', () {
    test('Simple save and load', () async {
      final credentials = Credentials(ProtectedValue.fromString('FooBar'));
      final saved = await (() async {
        final kdbx = kdbxForamt.create(credentials, 'CreateTest');
        final rootGroup = kdbx.body.rootGroup;
        final entry = KdbxEntry.create(kdbx, rootGroup);
        rootGroup.addEntry(entry);
        entry.setString(
            KdbxKey('Password'), ProtectedValue.fromString('LoremIpsum'));
        return kdbx.save();
      })();

//      print(ByteUtils.toHexList(saved));

      final kdbx = await kdbxForamt.read(saved, credentials);
      expect(
          kdbx.body.rootGroup.entries.first
              .getString(KdbxKey('Password'))
              .getText(),
          'LoremIpsum');
      File('test.kdbx').writeAsBytesSync(saved);
    });
  });
}
