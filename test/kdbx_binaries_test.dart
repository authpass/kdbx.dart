import 'dart:convert';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

void expectBinary(KdbxEntry entry, String key, dynamic matcher) {
  final binaries = entry.binaryEntries;
  expect(binaries, hasLength(1));
  final binary = binaries.first;
  expect(binary.key.key, key);
  expect(binary.value.value, matcher);
}

void main() {
  Logger.root.level = Level.ALL;
  PrintAppender().attachToLogger(Logger.root);

  group('kdbx3 attachment', () {
    void expectKeepass2binariesContents(KdbxEntry entry) {
      final binaries = entry.binaryEntries;
      expect(binaries, hasLength(3));
      for (final binary in binaries) {
        switch (binary.key.key) {
          case 'example1.txt':
            expect(utf8.decode(binary.value.value), 'content1 example\n\n');
            break;
          case 'example2.txt':
            expect(utf8.decode(binary.value.value), 'content2 example\n\n');
            break;
          case 'keepasslogo.jpeg':
            expect(binary.value.value, hasLength(7092));
            break;
          default:
            fail('invalid key. ${binary.key}');
        }
      }
    }

    test('read binary', () async {
      final file = await TestUtil.readKdbxFile('test/keepass2binaries.kdbx');
      final entry = file.body.rootGroup.entries.first;
      expectKeepass2binariesContents(entry);
    });
    test('read write read', () async {
      final fileRead =
          await TestUtil.readKdbxFile('test/keepass2binaries.kdbx');
      final saved = await fileRead.save();
      final file = await TestUtil.readKdbxFileBytes(saved);
      final entry = file.body.rootGroup.entries.first;
      expectKeepass2binariesContents(entry);
    });
  });
  group('kdbx4 attachment', () {
    test('read binary', () async {
      final file =
          await TestUtil.readKdbxFile('test/keepass2kdbx4binaries.kdbx');

      expect(file.body.rootGroup.entries, hasLength(2));
      expectBinary(file.body.rootGroup.entries.first, 'example2.txt',
          IsUtf8String('content2 example\n\n'));
      expectBinary(file.body.rootGroup.entries.last, 'keepasslogo.jpeg',
          hasLength(7092));
    });
  });
  test('read, write, read', () async {
    final fileRead =
        await TestUtil.readKdbxFile('test/keepass2kdbx4binaries.kdbx');
    final saved = await fileRead.save();
    final file = await TestUtil.readKdbxFileBytes(saved);
    expect(file.body.rootGroup.entries, hasLength(2));
    expectBinary(file.body.rootGroup.entries.first, 'example2.txt',
        IsUtf8String('content2 example\n\n'));
    expectBinary(
        file.body.rootGroup.entries.last, 'keepasslogo.jpeg', hasLength(7092));
  });
}

class IsUtf8String extends CustomMatcher {
  IsUtf8String(dynamic matcher) : super('is utf8 string', 'utf8', matcher);

  @override
  Object featureValueOf(dynamic actual) {
    if (actual is Uint8List) {
      return utf8.decode(actual);
    }
    return super.featureValueOf(actual);
  }
}
