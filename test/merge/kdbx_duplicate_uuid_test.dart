import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:test/test.dart';
import 'package:xml/xml.dart';

import '../internal/test_utils.dart';

/// Tests around the residue of the merge bug fixed after 2.5.0: a database
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

  String? passwordOf(KdbxEntry entry) =>
      entry.getString(KdbxKeyCommon.PASSWORD)?.getText();

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
    test('an object without a readable uuid does not break the read', () async {
      await withClock(fakeClock, () async {
        // Detection runs for every object on every read, and KdbxObject.uuid
        // throws where the <UUID> element is missing or doubled. Such a file
        // used to open fine, and has to keep opening.
        for (final mangle in <void Function(XmlElement node)>[
          (node) => XmlUtils.removeChildrenByName(node, KdbxXml.NODE_UUID),
          (node) => node.children.add(
            XmlElement(XmlName(KdbxXml.NODE_UUID)),
          ),
          (node) =>
              node.findElements(KdbxXml.NODE_UUID).single.children.clear(),
        ]) {
          final file = testUtil.createEmptyFile();
          testUtil.createEntry(file, file.body.rootGroup, 'user', 'pass');
          testUtil.createEntry(file, file.body.rootGroup, 'other', 'pass');
          for (final entry in file.body.rootGroup.entries) {
            mangle(entry.node);
          }
          proceedSeconds(10);

          final reread = await testUtil.saveAndRead(file);

          expect(reread.body.rootGroup.entries, hasLength(2));
          // and an unreadable or empty uuid is not an identity, so those
          // entries must not be reported - or repaired - as duplicates.
          expect(reread.duplicateUuidsOnOpen, isEmpty);
          expect(reread.findDuplicateUuidObjects(), isEmpty);
          expect(reread.mergeDuplicateUuidEntries(), isEmpty);
          expect(reread.body.rootGroup.entries, hasLength(2));
        }
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
          throwsA(
            isA<KdbxDuplicateUuidException>().having(
              (e) => e.uuid,
              'uuid',
              first.uuid,
            ),
          ),
        );
        expect(file.body.rootGroup.entries, hasLength(1));
      });
    });
  });

  group('moving a duplicate', () {
    test('deleting both copies throws without losing either', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        proceedSeconds(10);
        file.deleteEntry(file.body.rootGroup.entries.first);
        final victim = file.body.rootGroup.entries.single;

        // the recycle bin now holds the same uuid, so this cannot be done...
        expect(
          () => file.deleteEntry(victim),
          throwsA(isA<KdbxDuplicateUuidException>()),
        );

        // ... and nothing may have been moved out of the way before throwing:
        // an entry in no group at all is unreachable and the next save drops
        // it without a trace.
        expect(victim.parent, same(file.body.rootGroup));
        expect(file.body.rootGroup.entries, [same(victim)]);
        expect(file.body.rootGroup.getAllEntries(), hasLength(2));

        final reread = await testUtil.saveAndRead(file);
        expect(reread.body.rootGroup.getAllEntries(), hasLength(2));
        expect(
          reread.body.rootGroup.getAllEntries().map(usernameOf),
          containsAll(['original', 'duplicate']),
        );
      });
    });
    test('moving into a group without that uuid still works', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        final group = file.createGroup(
          parent: file.body.rootGroup,
          name: 'elsewhere',
        );
        proceedSeconds(10);
        final moved = file.body.rootGroup.entries.first;

        file.move(moved, group);

        expect(group.entries, [same(moved)]);
        expect(file.body.rootGroup.entries, hasLength(1));
      });
    });
    test('a move which changes nothing is not a collision', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final entry = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'user',
          'pass',
        );
        proceedSeconds(10);

        file.move(entry, file.body.rootGroup);

        expect(file.body.rootGroup.entries, [same(entry)]);
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
    test('a deleted object stops claiming its old group', () async {
      await withClock(fakeClock, () async {
        // No duplicates needed for this one: an object the merge removed used
        // to keep pointing at the group it was removed from, so code holding
        // it - an open screen, say - still saw a parent. `deletePermanently`
        // trusted that, recorded a second deleted object for the uuid, and
        // only then failed on the removal.
        final file = testUtil.createEmptyFile();
        testUtil.createEntry(file, file.body.rootGroup, 'victim', 'pass');
        final local = await testUtil.saveAndRead(file);
        proceedSeconds(10);
        final remote = await testUtil.saveAndRead(local);
        remote.deletePermanently(remote.body.rootGroup.entries.single);
        proceedSeconds(10);
        final doomed = local.body.rootGroup.entries.single;

        local.merge(remote);

        expect(local.body.rootGroup.entries, isEmpty);
        expect(doomed.parent, isNull);
        expect(doomed.isInRecycleBin(), isFalse);
        expect(local.body.deletedObjects, hasLength(1));

        // and the operations an app might still offer for it refuse cleanly,
        // without writing anything.
        expect(() => local.deletePermanently(doomed), throwsA(isStateError));
        expect(
          () => local.move(doomed, local.body.rootGroup),
          throwsA(isStateError),
        );
        expect(local.body.deletedObjects, hasLength(1));
      });
    });
    test(
      'a deletion of one copy, while the other stays, removes neither',
      () async {
        await withClock(fakeClock, () async {
          final file = await createFileWithDuplicateEntry();
          final other = await testUtil.saveAndRead(file);
          proceedSeconds(10);
          other.deletePermanently(other.body.rootGroup.entries.first);
          expect(other.body.rootGroup.entries, hasLength(1));

          final merge = file.merge(other);
          // the other file still shows the uuid live, next to its record, so
          // the record is void - like any a file holds for an object it still
          // has, see MergeDeletionRecordDropped. Both copies used to go here,
          // the one the other file kept as well.
          expect(file.body.rootGroup.entries, hasLength(2));
          expect(file.body.deletedObjects, isEmpty);
          expect(
            merge.events.whereType<MergeDeletionRecordDropped>(),
            hasLength(1),
          );
        });
      },
    );
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
        // the newer of the two copies survives, with its own content...
        expect(usernameOf(survivor), 'duplicate');
        expect(passwordOf(survivor), 'pass2');
        // ... and the other one lives on in its history, with its content -
        // nothing may be dropped, which is the whole point of folding rather
        // than deleting. Exactly one revision, no snapshot of the survivor's
        // own current state.
        expect(survivor.history, hasLength(1));
        expect(usernameOf(survivor.history.single), 'original');
        expect(passwordOf(survivor.history.single), 'pass1');
        // the uuid is not deleted - it is still in use by the survivor.
        expect(file.body.deletedObjects, isEmpty);

        final reread = await testUtil.saveAndRead(file);
        expect(reread.duplicateUuidsOnOpen, isEmpty);
        expect(reread.body.rootGroup.entries, hasLength(1));
        final rereadSurvivor = reread.body.rootGroup.entries.single;
        expect(rereadSurvivor.history, hasLength(1));
        expect(passwordOf(rereadSurvivor.history.single), 'pass1');
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
    test('two copies with the same timestamp keep both contents', () async {
      await withClock(fakeClock, () async {
        // the fixture above deliberately advances the clock between the two
        // entries. Without that they tie, and a fold which identifies
        // revisions by last modification time alone can drop one silently.
        final file = testUtil.createEmptyFile();
        final a = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'a',
          'pass-a',
        );
        final b = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'b',
          'pass-b',
        );
        b.forceSetUuid(a.uuid);
        final reread = await testUtil.saveAndRead(file);
        final entries = reread.body.rootGroup.entries;
        expect(
          entries[0].times.lastModificationTime.get(),
          entries[1].times.lastModificationTime.get(),
          reason: 'the timestamps have to tie for this to be a real test',
        );
        proceedSeconds(20);

        expect(reread.mergeDuplicateUuidEntries(), hasLength(1));

        final survivor = reread.body.rootGroup.entries.single;
        final everywhere = [
          passwordOf(survivor),
          ...survivor.history.map(passwordOf),
        ];
        expect(everywhere, containsAll(['pass-a', 'pass-b']));
      });
    });
    test('three copies of one uuid all fold in', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final first = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'one',
          'p1',
        );
        for (final name in ['two', 'three']) {
          proceedSeconds(10);
          testUtil
              .createEntry(file, file.body.rootGroup, name, 'p-$name')
              .forceSetUuid(first.uuid);
        }
        proceedSeconds(10);
        final reread = await testUtil.saveAndRead(file);
        expect(reread.body.rootGroup.entries, hasLength(3));

        expect(reread.mergeDuplicateUuidEntries(), hasLength(1));

        final survivor = reread.body.rootGroup.entries.single;
        expect(usernameOf(survivor), 'three');
        expect(
          survivor.history.map(usernameOf),
          containsAll(['one', 'two']),
        );
        expect(reread.findDuplicateUuidObjects(), isEmpty);
      });
    });
    test('a copy in the recycle bin never wins', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        // the user deletes one of the two identical looking entries.
        proceedSeconds(10);
        file.deleteEntry(file.body.rootGroup.entries.first);
        final visible = file.body.rootGroup.entries.single;
        expect(file.recycleBin!.entries, hasLength(1));
        // the move alone no longer bumps lastModificationTime - a move is a
        // change of location, not of the entry - so edit the trashed copy to
        // make it the newest, which is the case this test is about. The
        // username is left alone, it is what the assertions below go by.
        proceedSeconds(10);
        file.recycleBin!.entries.single.setString(
          KdbxKeyCommon.URL,
          PlainValue('https://example.com'),
        );
        expect(
          file.recycleBin!.entries.single.wasModifiedAfter(visible),
          isTrue,
          reason:
              'the trashed copy has to be the newest for this to be a '
              'real test',
        );
        proceedSeconds(10);

        file.mergeDuplicateUuidEntries();

        // the entry the user can see survives, in its own group.
        expect(file.body.rootGroup.entries, hasLength(1));
        expect(file.body.rootGroup.entries.single, same(visible));
        expect(usernameOf(file.body.rootGroup.entries.single), 'duplicate');
        expect(file.recycleBin!.entries, isEmpty);
        expect(visible.history.map(usernameOf), contains('original'));
      });
    });
    test('repairing does not bump the survivor', () async {
      await withClock(fakeClock, () async {
        final file = await createFileWithDuplicateEntry();
        final before = file.body.rootGroup.entries
            .map((e) => e.times.lastModificationTime.get())
            .reduce((a, b) => a!.isAfter(b!) ? a : b);
        proceedSeconds(3600);

        file.mergeDuplicateUuidEntries();

        // a repaired entry must not look newer than it is, or it would win
        // every later merge against genuinely newer content elsewhere.
        final survivor = file.body.rootGroup.entries.single;
        expect(survivor.times.lastModificationTime.get(), before);
        // and it must not have collected a snapshot of its own current state.
        expect(
          survivor.history.map(usernameOf).where((e) => e == 'duplicate'),
          isEmpty,
        );
      });
    });
    test('copies in other groups are folded in too', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final group1 = file.createGroup(
          parent: file.body.rootGroup,
          name: 'group1',
        );
        final group2 = file.createGroup(
          parent: file.body.rootGroup,
          name: 'group2',
        );
        final inGroup1 = testUtil.createEntry(file, group1, 'in-g1', 'p1');
        proceedSeconds(10);
        final inGroup2 = testUtil.createEntry(file, group2, 'in-g2', 'p2');
        inGroup2.forceSetUuid(inGroup1.uuid);
        proceedSeconds(10);
        final reread = await testUtil.saveAndRead(file);

        expect(reread.mergeDuplicateUuidEntries(), hasLength(1));

        // the newer copy survives where it is; group1 loses the entry
        // altogether, with its content kept as history.
        final groups = reread.body.rootGroup.groups;
        final g1 = groups.firstWhere((g) => g.name.get() == 'group1');
        final g2 = groups.firstWhere((g) => g.name.get() == 'group2');
        expect(g1.entries, isEmpty);
        expect(g2.entries, hasLength(1));
        expect(usernameOf(g2.entries.single), 'in-g2');
        expect(g2.entries.single.history.map(usernameOf), contains('in-g1'));
      });
    });
    test(
      'repeatedly merging an unrepaired replica keeps it repaired',
      () async {
        await withClock(fakeClock, () async {
          final file = await createFileWithDuplicateEntry();
          final unrepaired = await testUtil.saveAndRead(file);
          proceedSeconds(10);
          file.mergeDuplicateUuidEntries();

          for (var i = 0; i < 3; i++) {
            proceedSeconds(10);
            file.merge(unrepaired);
          }

          // syncing against a device which has not been repaired yet must not
          // bring the copies back, however often it happens.
          expect(file.body.rootGroup.entries, hasLength(1));
          expect(file.findDuplicateUuidObjects(), isEmpty);
          expect(usernameOf(file.body.rootGroup.entries.single), 'duplicate');
          // NB the survivor's history does grow by one revision per merge, but
          // that is not specific to a repaired entry: `KdbxEntry.merge`'s
          // outgoing-changes branch looks for *our* last modification time in
          // our own history, which is never there, so it re-adds the incoming
          // revision every time. Reproduced on an ordinary entry with no
          // duplicate uuids anywhere; left for its own fix.
        });
      },
    );
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
