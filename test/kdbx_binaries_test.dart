import 'dart:convert';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

void expectBinary(KdbxEntry entry, String key, dynamic matcher) {
  final binaries = entry.binaryEntries;
  expect(binaries, hasLength(1));
  final binary = binaries.first;
  expect(binary.key.key, key);
  expect(binary.value.value, matcher);
}

Future<void> _testAddNewAttachment(String filePath) async {
  final saved = await (() async {
    final f = await TestUtil().readKdbxFile(filePath);
    final entry = KdbxEntry.create(f, f.body.rootGroup);
    entry.label = 'addattachment';
    f.body.rootGroup.addEntry(entry);
    expect(entry.binaryEntries, hasLength(0));
    entry.createBinary(
        isProtected: false,
        name: 'test.txt',
        bytes: utf8.encode('Content1') as Uint8List);
    entry.createBinary(
        isProtected: false,
        name: 'test.txt',
        bytes: utf8.encode('Content2') as Uint8List);
    return await f.save();
  })();
  {
    final file = await TestUtil().readKdbxFileBytes(saved);
    final entry = file.body.rootGroup.entries
        .firstWhere((e) => e.label == 'addattachment');
    final binaries = entry.binaryEntries.toList();
    expect(entry.binaryEntries, hasLength(2));
    expect(binaries[0].key.key, 'test.txt');
    expect(binaries[0].value.value, IsUtf8String('Content1'));
    // must have been renamed.
    expect(binaries[1].key.key, 'test1.txt');
    expect(binaries[1].value.value, IsUtf8String('Content2'));
  }
}

void main() {
  final testUtil = TestUtil();

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
      final file = await testUtil.readKdbxFile('test/keepass2binaries.kdbx');
      final entry = file.body.rootGroup.entries.first;
      expectKeepass2binariesContents(entry);
    });
    test('read write read', () async {
      final fileRead =
          await testUtil.readKdbxFile('test/keepass2binaries.kdbx');
      final saved = await fileRead.save();
      final file = await testUtil.readKdbxFileBytes(saved);
      final entry = file.body.rootGroup.entries.first;
      expectKeepass2binariesContents(entry);
    });
    test('modify file with binary in history', () async {
      final fileRead =
          await testUtil.readKdbxFile('test/keepass2binaries.kdbx');
      void updateEntry(KdbxFile file) {
        final entry = fileRead.body.rootGroup.entries.first;
        entry.setString(KdbxKeyCommon.TITLE, PlainValue('example'));
      }

      updateEntry(fileRead);
      final saved = await fileRead.save();
      final file = await testUtil.readKdbxFileBytes(saved);
      await file.save();
    });
    test('Add new attachment', () async {
      await _testAddNewAttachment('test/keepass2binaries.kdbx');
    });
    test('Remove attachment', () async {
      final saved = await (() async {
        final file = await testUtil.readKdbxFile('test/keepass2binaries.kdbx');
        final entry = file.body.rootGroup.entries.first;
        expectKeepass2binariesContents(entry);
        expect(file.ctx.binariesIterable, hasLength(3));
        entry.removeBinary(KdbxKey('example1.txt'));
        expect(file.ctx.binariesIterable, hasLength(3));
        return await file.save();
      })();
      final file = await testUtil.readKdbxFileBytes(saved);
      final entry = file.body.rootGroup.entries.first;
      expect(entry.binaryEntries, hasLength(2));
      expect(entry.binaryEntries.map((e) => (e.key.key)),
          ['example2.txt', 'keepasslogo.jpeg']);
      // the file itself will contain 3 items, because it is still
      // available in history.
      expect(file.ctx.binariesIterable, hasLength(3));
      expect(entry.history.last.binaryEntries, hasLength(3));
      // make sure the file can still be saved.
      await file.save();
    });
    test('keepassxc compatibility', () async {
      // keepass has files in arbitrary sort order.
      final file = await testUtil
          .readKdbxFile('test/test_files/binarytest-keepassxc.kdbx');
      final entry = file.body.rootGroup.entries.first;
      for (final name in ['a', 'b', 'c', 'd', 'e']) {
        expect(
          utf8.decode(entry.getBinary(KdbxKey('$name.txt'))!.value).trim(),
          name,
        );
      }
    });
  }, tags: ['kdbx3']);
  group('kdbx4 attachment', () {
    test('read binary', () async {
      final file =
          await testUtil.readKdbxFile('test/keepass2kdbx4binaries.kdbx');

      expect(file.body.rootGroup.entries, hasLength(2));
      expectBinary(file.body.rootGroup.entries.first, 'example2.txt',
          IsUtf8String('content2 example\n\n'));
      expectBinary(file.body.rootGroup.entries.last, 'keepasslogo.jpeg',
          hasLength(7092));
    });
    test('read, write, read kdbx4', () async {
      final fileRead =
          await testUtil.readKdbxFile('test/keepass2kdbx4binaries.kdbx');
      final saved = await fileRead.save();
      final file = await testUtil.readKdbxFileBytes(saved);
      expect(file.body.rootGroup.entries, hasLength(2));
      expectBinary(file.body.rootGroup.entries.first, 'example2.txt',
          IsUtf8String('content2 example\n\n'));
      expectBinary(file.body.rootGroup.entries.last, 'keepasslogo.jpeg',
          hasLength(7092));
    });
    test('remove attachment kdbx4', () async {
      final saved = await (() async {
        final file =
            await testUtil.readKdbxFile('test/keepass2kdbx4binaries.kdbx');
        final entry = file.body.rootGroup.entries.first;
        expectBinary(file.body.rootGroup.entries.first, 'example2.txt',
            IsUtf8String('content2 example\n\n'));
        expectBinary(file.body.rootGroup.entries.last, 'keepasslogo.jpeg',
            hasLength(7092));
        expect(file.ctx.binariesIterable, hasLength(2));
        entry.removeBinary(KdbxKey('example2.txt'));
        // the binary remains in the file, since it is referenced in the history
        expect(file.ctx.binariesIterable, hasLength(2));
        expect(file.dirtyObjects, [entry]);
        return await file.save();
      })();
      final file = await testUtil.readKdbxFileBytes(saved);
      final entry = file.body.rootGroup.entries.first;
      expect(entry.binaryEntries, hasLength(0));
      expectBinary(file.body.rootGroup.entries.last, 'keepasslogo.jpeg',
          hasLength(7092));
      expect(file.ctx.binariesIterable, hasLength(2));
    });
    test('Add new attachment kdbx4', () async {
      await _testAddNewAttachment('test/keepass2kdbx4binaries.kdbx');
    });
  }, tags: ['kdbx4']);
}

class IsUtf8String extends CustomMatcher {
  IsUtf8String(dynamic matcher) : super('is utf8 string', 'utf8', matcher);

  @override
  Object? featureValueOf(dynamic actual) {
    if (actual is Uint8List) {
      return utf8.decode(actual);
    }
    return super.featureValueOf(actual);
  }
}
