import 'dart:io';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

void main() {
  Logger.root.level = Level.ALL;
  PrintAppender().attachToLogger(Logger.root);
  group('Reading', () {
    setUp(() {});

    test('First Test', () async {
      final data = await File('test/FooBar.kdbx').readAsBytes() as Uint8List;
      KdbxFormat.read(data, Credentials(ProtectedValue.fromString('FooBar')));
    });
  });

  group('Creating', () {
    test('Simple create', () {
      final kdbx = KdbxFormat.create(Credentials(ProtectedValue.fromString('FooBar')), 'CreateTest');
      expect(kdbx, isNotNull);
      expect(kdbx.body.rootGroup, isNotNull);
      expect(kdbx.body.rootGroup.name.get(), 'CreateTest');
      expect(kdbx.body.meta.databaseName.get(), 'CreateTest');
      print(kdbx.body.toXml().toXmlString(pretty: true));
    });
    test('Create Entry', () {
      final kdbx = KdbxFormat.create(Credentials(ProtectedValue.fromString('FooBar')), 'CreateTest');
      final rootGroup = kdbx.body.rootGroup;
      rootGroup.addEntry(KdbxEntry.create(rootGroup));
      print(kdbx.body.toXml().toXmlString(pretty: true));
    });
  });
}
