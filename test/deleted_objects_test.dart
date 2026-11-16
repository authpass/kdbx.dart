@Tags(['kdbx4'])
library;

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';
import 'package:xml/xml.dart';

import 'internal/test_utils.dart';
import 'kdbx_test.dart';

final _logger = Logger('deleted_objects_test');

void main() {
  final testUtil = TestUtil();
  _logger.finest('Running deleted objects tests.');
  group('read tombstones', () {
    test('load/save keeps deleted objects.', () async {
      final orig = await testUtil.readKdbxFile(
        'test/test_files/tombstonetest.kdbx',
      );
      expect(orig.body.deletedObjects, hasLength(1));
      final dt = orig.body.deletedObjects.first.deletionTime.get()!;
      expect([dt.year, dt.month, dt.day], [2020, 8, 30]);
      final reload = await testUtil.saveAndRead(orig);
      expect(reload.body.deletedObjects, hasLength(1));
    });
  });
  group('delete to trash', () {
    test('move to trash, read previous parent', () {
      final file = testUtil.createEmptyFile();
      final g = file.body.rootGroup;
      final entry = testUtil.createEntry(file, g, 'foo', 'bar');
      expect(g.getAllGroupsAndEntries(), hasLength(2));
      file.deleteEntry(entry);
      // root group, entry and trash group.
      expect(g.getAllGroupsAndEntries(), hasLength(3));
      expect(entry.previousParentGroup.get(), g.uuid);
    });
  });
  group('delete permanently', () {
    test('delete entry', () async {
      final file = testUtil.createEmptyFile();
      final g = file.body.rootGroup;
      final entry = testUtil.createEntry(file, g, 'foo', 'bar');
      // Only a deletion other copies could notice is worth recording, so the
      // entry has to reach the file first. See
      // [KdbxObject.isKnownOutsideThisSession].
      await file.save();
      expect(g.getAllGroupsAndEntries().length, 2);
      file.deleteEntry(entry);
      // moved into trash bin
      expect(g.getAllGroupsAndEntries().length, 3);
      // now delete from trash
      file.deletePermanently(entry);
      expect(g.getAllGroupsAndEntries().length, 2);
      final xml = file.body.generateXml(FakeProtectedSaltGenerator());
      final objects = xml.findAllElements(KdbxXml.NODE_DELETED_OBJECT);
      expect(objects.length, 1);
      expect(
        objects.first.findElements(KdbxXml.NODE_UUID).first.text,
        entry.uuid.uuid,
      );
    });
    test('delete group', () async {
      final file = testUtil.createEmptyFile();
      final rootGroup = file.body.rootGroup;
      final g = file.createGroup(parent: rootGroup, name: 'group');
      final objs = [
        g,
        testUtil.createEntry(file, g, 'foo', 'bar'),
        testUtil.createEntry(file, g, 'foo2', 'bar2'),
        testUtil.createEntry(file, g, 'foo3', 'bar3'),
      ];

      await file.save();

      expect(rootGroup.getAllGroupsAndEntries().length, 5);
      file.deletePermanently(g);
      expect(rootGroup.getAllGroupsAndEntries().length, 1);
      final xml = file.body.generateXml(FakeProtectedSaltGenerator());
      final objects = xml.findAllElements(KdbxXml.NODE_DELETED_OBJECT);
      expect(objects.length, 4);
      expect(
        objects.map((e) => e.findElements(KdbxXml.NODE_UUID).first.text),
        objs.map((o) => o.uuid.uuid),
      );
    });
  });
  group('delete permanently, nothing to announce', () {
    List<String?> recordedUuids(KdbxFile file) => file.body
        .generateXml(FakeProtectedSaltGenerator())
        .findAllElements(KdbxXml.NODE_DELETED_OBJECT)
        .map((e) => e.findElements(KdbxXml.NODE_UUID).first.innerText)
        .toList();

    test('no record for an entry that was never saved', () async {
      final file = testUtil.createEmptyFile();
      final g = file.body.rootGroup;
      final entry = testUtil.createEntry(file, g, 'foo', 'bar');
      expect(entry.isKnownOutsideThisSession, isFalse);

      file.deletePermanently(entry);

      // Nothing anywhere holds this uuid, so a record naming it would be junk
      // that every merge from here on carries to every replica.
      expect(recordedUuids(file), isEmpty);
      expect(file.body.deletedObjects, isEmpty);
    });

    test('no record for an entry added to a group others know', () async {
      final file = testUtil.createEmptyFile();
      final g = file.createGroup(parent: file.body.rootGroup, name: 'group');
      final old = testUtil.createEntry(file, g, 'old', 'old');
      await file.save();
      final fresh = testUtil.createEntry(file, g, 'fresh', 'fresh');

      file.deletePermanently(g);

      // The group and the saved entry have to be announced; the one added
      // since the save has not been anywhere.
      expect(
        recordedUuids(file),
        unorderedEquals([g.uuid.uuid, old.uuid.uuid]),
      );
      expect(recordedUuids(file), isNot(contains(fresh.uuid.uuid)));
    });

    test('records an entry a merge brought in, unsaved as it is', () async {
      final file = testUtil.createEmptyFile();
      testUtil.createEntry(file, file.body.rootGroup, 'test1', 'test1');
      final local = await testUtil.saveAndRead(file);
      final remote = await testUtil.saveAndRead(local);

      final added = testUtil.createEntry(
        remote,
        remote.body.rootGroup,
        'added',
        'added',
      );
      await remote.save();

      local.merge(remote);
      final imported = local.body.rootGroup.entries.firstWhere(
        (e) => e.uuid == added.uuid,
      );
      // Never saved in this copy, and dirty - but the device it came from
      // holds it, so dropping it here has to be told to that device or the
      // next sync brings it straight back.
      expect(imported.isKnownOutsideThisSession, isTrue);

      local.deletePermanently(imported);

      expect(recordedUuids(local), contains(added.uuid.uuid));
    });

    test('records a group a merge brought in, unsaved as it is', () async {
      final file = testUtil.createEmptyFile();
      testUtil.createEntry(file, file.body.rootGroup, 'test1', 'test1');
      final local = await testUtil.saveAndRead(file);
      final remote = await testUtil.saveAndRead(local);

      final added = remote.createGroup(
        parent: remote.body.rootGroup,
        name: 'added',
      );
      await remote.save();

      local.merge(remote);
      final imported = local.body.rootGroup.groups.firstWhere(
        (g) => g.uuid == added.uuid,
      );
      expect(imported.isKnownOutsideThisSession, isTrue);

      local.deletePermanently(imported);

      expect(recordedUuids(local), contains(added.uuid.uuid));
    });
  });
  group('markClean', () {
    test('add, go back: the file looks untouched again', () async {
      final file = testUtil.createEmptyFile();
      final group = file.createGroup(
        parent: file.body.rootGroup,
        name: 'group',
      );
      testUtil.createEntry(file, group, 'kept', 'kept');
      await file.save();
      expect(file.isDirty, isFalse);

      // the add button, and nothing entered
      final blank = KdbxEntry.create(file, group);
      group.addEntry(blank);
      expect(file.isDirty, isTrue);

      // going back
      file.deletePermanently(blank);
      file.markClean([blank, group]);

      expect(file.isDirty, isFalse);
      expect(file.dirtyObjects, isEmpty);
      // and nothing of the entry is left to reach any other copy.
      expect(file.body.deletedObjects, isEmpty);
      expect(group.entries, hasLength(1));
    });

    test('leaves everything not listed dirty', () async {
      final file = testUtil.createEmptyFile();
      final group = file.body.rootGroup;
      final other = testUtil.createEntry(file, group, 'other', 'other');
      await file.save();

      final blank = KdbxEntry.create(file, group);
      group.addEntry(blank);
      other.setString(KdbxKeyCommon.USER_NAME, PlainValue('edited'));

      file.deletePermanently(blank);
      file.markClean([blank]);

      // the user's own edit is still waiting to be saved.
      expect(file.isDirty, isTrue);
      expect(file.dirtyObjects, contains(other));
      expect(file.dirtyObjects, isNot(contains(blank)));
    });

    test('is not a save: the object stays one no copy holds', () async {
      final file = testUtil.createEmptyFile();
      final group = file.body.rootGroup;
      final entry = testUtil.createEntry(file, group, 'foo', 'bar');

      file.markClean([entry]);

      expect(entry.isDirty, isFalse);
      // Marking clean drops the reason to save; it does not put the entry in
      // a file. Deleting it still has nobody to announce to.
      expect(entry.isKnownOutsideThisSession, isFalse);
      file.deletePermanently(entry);
      expect(file.body.deletedObjects, isEmpty);
    });

    test('does not revert the values it stops saving', () async {
      final file = testUtil.createEmptyFile();
      final entry = testUtil.createEntry(
        file,
        file.body.rootGroup,
        'foo',
        'bar',
      );
      await file.save();
      entry.setString(KdbxKeyCommon.USER_NAME, PlainValue('edited'));

      file.markClean([entry]);

      expect(file.isDirty, isFalse);
      // Only the bookkeeping changed. The edit is still in memory, and now
      // nothing will save it - which is why this is for objects whose state
      // has stopped mattering.
      expect(
        entry.getString(KdbxKeyCommon.USER_NAME)?.getText(),
        'edited',
      );
    });
  });
}
