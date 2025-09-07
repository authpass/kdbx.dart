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
}
