import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import '../internal/test_utils.dart';

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

  group('moving objects', () {
    test(
      'updates locationChanged, but is not a modification of the entry',
      () async => await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final entry = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'user1',
          'pass1',
        );
        final subGroup = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Sub Group',
        );
        proceedSeconds(10);
        final modifiedBefore = entry.times.lastModificationTime.get();

        file.move(entry, subGroup);

        expect(entry.times.locationChanged.get(), now.toUtc());
        expect(entry.times.lastModificationTime.get(), modifiedBefore);
        expect(entry.history, isEmpty);
        expect(entry.isDirty, isTrue);
      }),
    );
  });

  group('merging objects which were moved', () {
    test(
      'keeps the changes of an entry which was edited and moved',
      () async => await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        testUtil.createEntry(file, file.body.rootGroup, 'user1', 'pass1');
        final subGroup = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Sub Group',
        );
        proceedSeconds(10);

        final fileLocal = await testUtil.saveAndRead(file);
        final fileRemoteMod = await testUtil.saveAndRead(file);
        proceedSeconds(10);

        // in the remote copy the entry is edited *and* moved.
        final remoteEntry = fileRemoteMod.body.rootGroup.entries.first;
        remoteEntry.setString(KdbxKeyCommon.TITLE, PlainValue('edited'));
        fileRemoteMod.move(
          remoteEntry,
          fileRemoteMod.findGroupByUuid(subGroup.uuid),
        );
        final fileRemote = await testUtil.saveAndRead(fileRemoteMod);
        proceedSeconds(10);

        fileLocal.merge(fileRemote);

        final mergedEntry = fileLocal.body.rootGroup
            .getAllEntries()
            .singleWhere((entry) => entry.uuid == remoteEntry.uuid);
        // the move must have been applied ...
        expect(mergedEntry.parent!.uuid, subGroup.uuid);
        // ... and so must the edit.
        expect(
          mergedEntry.getString(KdbxKeyCommon.TITLE)?.getText(),
          'edited',
        );
      }),
    );

    test(
      'leaves the history of an entry the other copy only moved alone',
      () async => await withClock(fakeClock, () async {
        var file = testUtil.createEmptyFile();
        final entry = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'user1',
          'pass1',
        );
        final subGroup = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Sub Group',
        );
        proceedSeconds(10);

        // two revisions, so there is a history to lose.
        for (final title in ['first', 'second']) {
          file = await testUtil.saveAndRead(file);
          file.body.rootGroup.entries.first.setString(
            KdbxKeyCommon.TITLE,
            PlainValue(title),
          );
          proceedSeconds(10);
        }
        final fileLocal = await testUtil.saveAndRead(file);
        expect(fileLocal.body.rootGroup.entries.first.history, hasLength(2));

        // the other copy only moves the entry, nothing is edited anywhere.
        final fileRemoteMod = await testUtil.saveAndRead(fileLocal);
        proceedSeconds(10);
        fileRemoteMod.move(
          fileRemoteMod.body.rootGroup.entries.first,
          fileRemoteMod.findGroupByUuid(subGroup.uuid),
        );
        final fileRemote = await testUtil.saveAndRead(fileRemoteMod);
        proceedSeconds(10);

        fileLocal.merge(fileRemote);

        final mergedEntry = fileLocal.body.rootGroup
            .getAllEntries()
            .singleWhere((e) => e.uuid == entry.uuid);
        expect(mergedEntry.parent!.uuid, subGroup.uuid);
        expect(mergedEntry.history, hasLength(2));
      }),
    );

    test(
      'keeps the newer of two conflicting moves',
      () async => await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final entry = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'user1',
          'pass1',
        );
        final groupA = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Group A',
        );
        final groupB = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Group B',
        );
        proceedSeconds(10);

        final fileLocal = await testUtil.saveAndRead(file);
        final fileRemoteMod = await testUtil.saveAndRead(file);

        // the remote copy moves the entry into group B ...
        proceedSeconds(10);
        fileRemoteMod.move(
          fileRemoteMod.body.rootGroup.entries.first,
          fileRemoteMod.findGroupByUuid(groupB.uuid),
        );
        final fileRemote = await testUtil.saveAndRead(fileRemoteMod);

        // ... but we moved it into group A afterwards, so we win.
        proceedSeconds(10);
        fileLocal.move(
          fileLocal.body.rootGroup.entries.first,
          fileLocal.findGroupByUuid(groupA.uuid),
        );
        proceedSeconds(10);

        fileLocal.merge(fileRemote);

        expect(
          fileLocal.body.rootGroup
              .getAllEntries()
              .singleWhere((e) => e.uuid == entry.uuid)
              .parent!
              .uuid,
          groupA.uuid,
        );
      }),
    );

    test(
      'keeps the changes of a group which was renamed and moved',
      () async => await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final groupA = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Group A',
        );
        final groupB = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Group B',
        );
        proceedSeconds(10);

        final fileLocal = await testUtil.saveAndRead(file);
        final fileRemoteMod = await testUtil.saveAndRead(file);
        proceedSeconds(10);

        // in the remote copy group A is renamed *and* moved into group B.
        final remoteGroupA = fileRemoteMod.findGroupByUuid(groupA.uuid);
        remoteGroupA.name.set('Group A renamed');
        fileRemoteMod.move(
          remoteGroupA,
          fileRemoteMod.findGroupByUuid(groupB.uuid),
        );
        final fileRemote = await testUtil.saveAndRead(fileRemoteMod);
        proceedSeconds(10);

        fileLocal.merge(fileRemote);

        final mergedGroupA = fileLocal.findGroupByUuid(groupA.uuid);
        expect(mergedGroupA.parent!.uuid, groupB.uuid);
        expect(mergedGroupA.name.get(), 'Group A renamed');
      }),
    );

    test(
      'keeps the changes of the group an entry was moved out of',
      () async => await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        final groupA = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Group A',
        );
        final groupB = file.createGroup(
          parent: file.body.rootGroup,
          name: 'Group B',
        );
        final entry = testUtil.createEntry(file, groupB, 'user1', 'pass1');
        proceedSeconds(10);

        final fileLocal = await testUtil.saveAndRead(file);
        final fileRemoteMod = await testUtil.saveAndRead(file);
        proceedSeconds(10);

        // in the remote copy group B is renamed and its entry is moved into
        // group A, which is merged before group B.
        fileRemoteMod.findGroupByUuid(groupB.uuid).name.set('Group B renamed');
        fileRemoteMod.move(
          fileRemoteMod.body.rootGroup.getAllEntries().singleWhere(
            (e) => e.uuid == entry.uuid,
          ),
          fileRemoteMod.findGroupByUuid(groupA.uuid),
        );
        final fileRemote = await testUtil.saveAndRead(fileRemoteMod);
        proceedSeconds(10);

        fileLocal.merge(fileRemote);

        expect(
          fileLocal.body.rootGroup
              .getAllEntries()
              .singleWhere((e) => e.uuid == entry.uuid)
              .parent!
              .uuid,
          groupA.uuid,
        );
        expect(
          fileLocal.findGroupByUuid(groupB.uuid).name.get(),
          'Group B renamed',
        );
      }),
    );
  });
}
