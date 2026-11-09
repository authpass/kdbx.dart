import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:test/test.dart';

import '../internal/test_utils.dart';

/// Tests around the residue of the merge bug fixed in 2.5.0+1: a database
/// which carries two or more *live* entries sharing one uuid. The bug itself
/// is fixed, so these files can no longer be produced through merging - but
/// they exist on users' disks, so the fixtures build them directly.
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

  /// A file with two live entries in the root group which share a uuid. The
  /// second one is the newer of the two.
  Future<KdbxFile> createFileWithDuplicateEntry() async {
    final file = testUtil.createEmptyFile();
    final original = testUtil.createEntry(
      file,
      file.body.rootGroup,
      'original',
      'pass1',
    );
    proceedSeconds(10);
    final duplicate = testUtil.createEntry(
      file,
      file.body.rootGroup,
      'duplicate',
      'pass2',
    );
    // the uuid can only be forced on after `addEntry`, which now rejects a
    // duplicate - just like the merge bug did it, which created the entry
    // before copying the uuid over.
    duplicate.forceSetUuid(original.uuid);
    proceedSeconds(10);
    return await testUtil.saveAndRead(file);
  }

  String? usernameOf(KdbxEntry entry) =>
      entry.getString(KdbxKeyCommon.USER_NAME)?.getText();

  group('duplicate uuid detection', () {
    test('a file with duplicates round trips and is reported', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        final entries = file.body.rootGroup.entries;
        expect(entries, hasLength(2));
        expect(entries[0].uuid, entries[1].uuid);

        expect(file.duplicateUuidsOnOpen, hasLength(1));
        expect(file.duplicateUuidsOnOpen, contains(entries[0].uuid));
        expect(
          file.findDuplicateUuidObjects()[entries[0].uuid],
          hasLength(2),
        );

        // the whole point is that such files sit on disk, so make sure the
        // fixture survives another round trip.
        final reread = await testUtil.saveAndRead(file);
        expect(reread.body.rootGroup.entries, hasLength(2));
        expect(reread.duplicateUuidsOnOpen, hasLength(1));
      });
    });
    test('a healthy file reports nothing', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        testUtil.createEntry(file, file.body.rootGroup, 'user', 'pass');
        final reread = await testUtil.saveAndRead(file);
        expect(reread.duplicateUuidsOnOpen, isEmpty);
        expect(reread.findDuplicateUuidObjects(), isEmpty);
      });
    });
    test('history entries are not duplicates', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        testUtil.createEntry(file, file.body.rootGroup, 'user', 'pass');
        final saved = await testUtil.saveAndRead(file);
        proceedSeconds(10);
        saved.body.rootGroup.entries.single.setString(
          KdbxKeyCommon.USER_NAME,
          PlainValue('changed'),
        );
        final reread = await testUtil.saveAndRead(saved);
        expect(reread.body.rootGroup.entries.single.history, isNotEmpty);
        expect(reread.duplicateUuidsOnOpen, isEmpty);
      });
    });
    test('addEntry rejects a duplicate uuid', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final first = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'user',
          'pass',
        );
        final second = KdbxEntry.create(file, file.body.rootGroup)
          ..forceSetUuid(first.uuid);
        expect(
          () => file.body.rootGroup.addEntry(second),
          throwsA(isA<StateError>()),
        );
      });
    });
  });

  group('duplicate uuid in a merge', () {
    test('merging reports the duplicates instead of failing', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        final other = await testUtil.saveAndRead(file);
        proceedSeconds(10);
        final merge = file.merge(other);
        expect(merge.warnings, isNotEmpty);
        expect(
          merge.warnings.map((e) => e.debug).join('\n'),
          allOf(contains('Local file carries'), contains('Incoming file')),
        );
        // no copy was gained or lost by the merge.
        expect(file.body.rootGroup.entries, hasLength(2));
      });
    });
    test('an incoming deletion removes every copy', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        final other = await testUtil.saveAndRead(file);
        proceedSeconds(10);
        other.deletePermanently(other.body.rootGroup.entries.first);
        expect(other.body.rootGroup.entries, hasLength(1));

        file.merge(other);
        // both local copies carry the deleted uuid, so both have to go.
        expect(file.body.rootGroup.entries, isEmpty);
      });
    });
  });

  group('duplicate uuid repair', () {
    test('folds the duplicates into the surviving entry', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        final uuid = file.body.rootGroup.entries.first.uuid;
        proceedSeconds(10);

        final repaired = file.mergeDuplicateUuidEntries();
        expect(repaired, [uuid]);
        expect(file.findDuplicateUuidObjects(), isEmpty);
        // but the file still remembers what it looked like on disk.
        expect(file.duplicateUuidsOnOpen, contains(uuid));

        final survivor = file.body.rootGroup.entries.single;
        expect(survivor.uuid, uuid);
        // the newer of the two copies survives.
        expect(usernameOf(survivor), 'duplicate');
        // ... and the other one lives on in its history.
        expect(
          survivor.history.map(usernameOf),
          contains('original'),
        );
        // the uuid is not deleted - it is still in use by the survivor.
        expect(file.body.deletedObjects, isEmpty);

        final reread = await testUtil.saveAndRead(file);
        expect(reread.duplicateUuidsOnOpen, isEmpty);
        expect(reread.body.rootGroup.entries, hasLength(1));
        expect(
          reread.body.rootGroup.entries.single.history.map(usernameOf),
          contains('original'),
        );
      });
    });
    test('a repaired file stays repaired when merged again', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        // the other side is still the unrepaired copy, as it would be on a
        // device which has not been updated yet.
        final other = await testUtil.saveAndRead(file);
        proceedSeconds(10);
        file.mergeDuplicateUuidEntries();
        proceedSeconds(10);

        final merge = file.merge(other);
        expect(merge.warnings, isNotEmpty);
        expect(file.body.rootGroup.entries, hasLength(1));
        expect(file.findDuplicateUuidObjects(), isEmpty);
      });
    });
    test('a uuid shared with a group is left alone', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final entry = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'user',
          'pass',
        );
        final group = file.createGroup(
          parent: file.body.rootGroup,
          name: 'group',
        );
        group.forceSetUuid(entry.uuid);
        proceedSeconds(10);

        expect(file.mergeDuplicateUuidEntries(), isEmpty);
        expect(file.findDuplicateUuidObjects(), hasLength(1));
      });
    });
  });
}
