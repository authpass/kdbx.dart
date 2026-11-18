import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

void main() {
  final testUtil = TestUtil();

  /// A file as it is right after opening: nothing to save.
  Future<KdbxFile> openedFile() async {
    final file = await testUtil.saveAndRead(testUtil.createEmptyFile());
    expect(file.isDirty, isFalse);
    return file;
  }

  group('a change to the database settings', () {
    test('makes the file dirty, and saving cleans it', () async {
      final file = await openedFile();

      file.body.meta.databaseName.set('renamed');

      // a caller that saves when the file is dirty used to never save it.
      expect(file.isDirty, isTrue);
      await file.save();
      expect(file.isDirty, isFalse);
      final reread = await testUtil.saveAndRead(file);
      expect(reread.body.meta.databaseName.get(), 'renamed');
    });

    test('to the value it already has does not', () async {
      final file = await openedFile();

      file.body.meta.databaseName.set(file.body.meta.databaseName.get());
      file.body.meta.historyMaxItems.set(
        file.body.meta.historyMaxItems.get(),
      );

      expect(file.isDirty, isFalse);
    });

    test('in its custom data makes the file dirty', () async {
      final file = await openedFile();

      file.body.meta.customData['key'] = 'value';

      expect(file.isDirty, isTrue);
      await file.save();
      expect(file.isDirty, isFalse);
      // the same value once more is no change.
      file.body.meta.customData['key'] = 'value';
      expect(file.isDirty, isFalse);
    });

    test('adding a custom icon makes the file dirty', () async {
      final file = await openedFile();

      file.body.meta.addCustomIcon(
        KdbxCustomIcon(uuid: KdbxUuid.random(), data: Uint8List(4)),
      );

      expect(file.isDirty, isTrue);
    });

    test('changing the credentials makes the file dirty', () async {
      final file = await openedFile();

      file.credentials = Credentials(ProtectedValue.fromString('changed'));

      expect(file.isDirty, isTrue);
    });

    test('is announced on dirtyObjectsChanged', () async {
      final file = await openedFile();
      final announced = file.dirtyObjectsChanged.first.timeout(
        const Duration(seconds: 1),
      );

      file.body.meta.databaseDescription.set('described');

      await expectLater(announced, completes);
    });

    test('made while saving keeps the file dirty', () async {
      final file = await openedFile();
      file.body.meta.databaseName.set('first');

      await file.saveTo((bytes) async {
        expect(file.isDirty, isTrue);
        file.body.meta.databaseName.set('second');
        return bytes;
      });

      expect(file.isDirty, isTrue);
    });
  });

  test('saving a kdbx 3 file leaves it clean', () async {
    final file = await testUtil.readKdbxFile(
      'test/FooBar.kdbx',
      password: 'FooBar',
    );
    expect(file.header.version.major, 3);
    file.body.meta.databaseName.set('renamed');

    // saving writes the header hash into the settings, which is no change
    // to the database.
    await file.save();

    expect(file.isDirty, isFalse);
  }, tags: 'kdbx3');

  test('a merge that only changes a setting makes the file dirty', () async {
    var now = DateTime.utc(2020);
    await withClock(Clock(() => now), () async {
      final base = await openedFile();
      final local = await testUtil.saveAndRead(base);
      final remote = await testUtil.saveAndRead(base);
      now = now.add(const Duration(seconds: 10));
      remote.body.meta.databaseName.set('renamed elsewhere');
      final incoming = await testUtil.saveAndRead(remote);

      local.merge(incoming);

      expect(local.body.meta.databaseName.get(), 'renamed elsewhere');
      // and so the merge result is written back.
      expect(local.isDirty, isTrue);
    });
  });
}
