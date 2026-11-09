import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:kdbx/src/utils/print_utils.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';
import 'package:xml/xml.dart';

import '../internal/test_utils.dart';
import '../kdbx_test.dart';

final _logger = Logger('kdbx_merge_test');

void main() {
  final testUtil = TestUtil();
  var now = DateTime.fromMillisecondsSinceEpoch(0);

  final fakeClock = Clock(() => now);
  void proceedSeconds(int seconds) {
    now = now.add(Duration(seconds: seconds));
  }

  setUp(() {
    now = DateTime.fromMillisecondsSinceEpoch(0);
  });
  group('Simple merges', () {
    Future<KdbxFile> createSimpleFile() async {
      final file = testUtil.createEmptyFile();
      _createEntry(file, file.body.rootGroup, 'test1', 'test1');
      final subGroup = file.createGroup(
        parent: file.body.rootGroup,
        name: 'Sub Group',
      );
      _createEntry(file, subGroup, 'test2', 'test2');
      proceedSeconds(10);
      return await testUtil.saveAndRead(file);
    }

    test('Noop merge', () async {
      final file = await createSimpleFile();
      final file2 = await testUtil.saveAndRead(file);
      final merge = file.merge(file2);
      final set = Set<KdbxUuid>.from(merge.merged.keys);
      expect(set, hasLength(4));
      expect(merge.changes, isEmpty);
    });
    test('Username change', () async {
      await withClock(fakeClock, () async {
        final file = await createSimpleFile();

        final fileMod = await testUtil.saveAndRead(file);

        fileMod.body.rootGroup.entries.first.setString(
          KdbxKeyCommon.USER_NAME,
          PlainValue('changed.'),
        );
        _logger.info(
          'mod date: ${fileMod.body.rootGroup.entries.first.times.lastModificationTime.get()}',
        );
        final file2 = await testUtil.saveAndRead(fileMod);

        _logger.info('\n\n\nstarting merge.\n');
        final merge = file.merge(file2);
        expect(file.body.rootGroup.entries.first.history, hasLength(1));
        final set = Set<KdbxUuid>.from(merge.merged.keys);
        expect(set, hasLength(4));
        expect(merge.changes, hasLength(1));
      });
    });
    test(
      'Change Group Name',
      () async => await withClock(fakeClock, () async {
        final file = await createSimpleFile();

        final fileMod = await testUtil.saveAndRead(file);

        fileMod.body.rootGroup.groups.first.name.set('Sub Group New Name.');
        final file2 = await testUtil.saveAndRead(fileMod);
        final merge = file.merge(file2);
        final set = Set<KdbxUuid>.from(merge.merged.keys);
        expect(set, hasLength(4));
        expect(merge.changes, hasLength(1));
      }),
    );
    test(
      'Move Entry to recycle bin',
      () async => await withClock(fakeClock, () async {
        final file = await createSimpleFile();

        final fileMod = await testUtil.saveAndRead(file);

        expect(fileMod.recycleBin, isNull);
        fileMod.deleteEntry(fileMod.body.rootGroup.entries.first);
        expect(fileMod.recycleBin, isNotNull);
        final file2 = await testUtil.saveAndRead(fileMod);
        final merge = file.merge(file2);
        _logger.info(
          'Merged file:\n'
          '${KdbxPrintUtils().catGroupToString(file.body.rootGroup)}',
        );
        final set = Set<KdbxUuid>.from(merge.merged.keys);
        expect(set, hasLength(5));
        expect(
          Set<KdbxNode>.from(merge.changes.map<KdbxNode?>((e) => e.object)),
          hasLength(2),
        );
      }),
    );
    test(
      'permanently delete an entry',
      () async => await withClock(fakeClock, () async {
        final file = await createSimpleFile();
        final objCount = file.body.rootGroup.getAllGroupsAndEntries().length;
        final fileMod = await testUtil.saveAndRead(file);
        final entryDelete = fileMod.body.rootGroup.entries.first;
        fileMod.deletePermanently(entryDelete);
        expect(
          fileMod.body.rootGroup.getAllGroupsAndEntries(),
          hasLength(objCount - 1),
        );

        final file2 = await testUtil.saveAndRead(fileMod);
        final merge = file.merge(file2);
        _logger.info(
          'Merged file:\n'
          '${KdbxPrintUtils().catGroupToString(file.body.rootGroup)}',
        );
        expect(merge.deletedObjects, hasLength(1));
        expect(
          file.body.rootGroup.getAllGroupsAndEntries().length,
          objCount - 1,
        );
        final xml = file.body.generateXml(FakeProtectedSaltGenerator());
        final deleted = xml.findAllElements(KdbxXml.NODE_DELETED_OBJECT);
        expect(deleted, hasLength(1));
        expect(
          deleted.first.findAllElements(KdbxXml.NODE_UUID).map((e) => e.text),
          [entryDelete.uuid.uuid],
        );
      }),
    );
    test(
      'Add a new entry which already has history',
      () async => await withClock(fakeClock, () async {
        final file = await createSimpleFile();
        final objCount = file.body.rootGroup.getAllGroupsAndEntries().length;

        // create the new entry in a copy the local file has never seen,
        // then modify it once so it carries a single history revision.
        final fileMod = await testUtil.saveAndRead(file);
        final newEntry = _createEntry(
          fileMod,
          fileMod.body.rootGroup,
          'new1',
          'new1',
        );
        final newUuid = newEntry.uuid;
        final fileMod2 = await testUtil.saveAndRead(fileMod);
        proceedSeconds(10);
        final newEntryMod = fileMod2.body.rootGroup.entries.firstWhere(
          (e) => e.uuid == newUuid,
        );
        newEntryMod.setString(KdbxKeyCommon.USER_NAME, PlainValue('new2'));
        expect(newEntryMod.history, hasLength(1));

        final file2 = await testUtil.saveAndRead(fileMod2);
        final merge = file.merge(file2);
        _logger.info(
          'Merged file:\n'
          '${KdbxPrintUtils().catGroupToString(file.body.rootGroup)}',
        );

        // exactly one live entry for the new uuid, revisions in its history.
        final merged = file.body.rootGroup.entries.where(
          (e) => e.uuid == newUuid,
        );
        expect(merged, hasLength(1));
        expect(merged.single.history, hasLength(1));
        expect(
          merged.single.getString(KdbxKeyCommon.USER_NAME)!.getText(),
          'new2',
        );
        expect(
          merged.single.history.single
              .getString(KdbxKeyCommon.USER_NAME)!
              .getText(),
          'new1',
        );
        expect(
          file.body.rootGroup.getAllGroupsAndEntries(),
          hasLength(objCount + 1),
        );
        expect(merge.merged.keys, contains(newUuid));
      }),
    );
  });
}

KdbxEntry _createEntry(
  KdbxFile file,
  KdbxGroup group,
  String username,
  String password,
) {
  final entry = KdbxEntry.create(file, group);
  group.addEntry(entry);
  entry.setString(KdbxKeyCommon.USER_NAME, PlainValue(username));
  entry.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(password));
  return entry;
}
