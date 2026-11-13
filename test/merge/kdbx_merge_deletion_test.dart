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

  /// A saved file with an entry in the root group and a group holding two
  /// more.
  Future<KdbxFile> createBase() async {
    final file = testUtil.createEmptyFile();
    testUtil.createEntry(file, file.body.rootGroup, 'user', 'base');
    final group = file.createGroup(parent: file.body.rootGroup, name: 'group');
    testUtil.createEntry(file, group, 'first', 'base');
    testUtil.createEntry(file, group, 'second', 'base');
    proceedSeconds(10);
    return await testUtil.saveAndRead(file);
  }

  Future<(KdbxFile, KdbxFile)> twoCopies() async {
    final base = await createBase();
    return (
      await testUtil.saveAndRead(base),
      await testUtil.saveAndRead(base),
    );
  }

  KdbxEntry? entryNamed(KdbxFile file, String user) => file.body.rootGroup
      .getAllEntries()
      .where(
        (entry) => entry.getString(KdbxKeyCommon.USER_NAME)?.getText() == user,
      )
      .firstOrNull;

  KdbxGroup? groupNamed(KdbxFile file, String name) => file.body.rootGroup
      .getAllGroups()
      .where((group) => group.name.get() == name)
      .firstOrNull;

  void setPassword(KdbxEntry entry, String value) =>
      entry.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value));

  Set<String> liveUuids(KdbxFile file) => file.body.rootGroup
      .getAllGroupsAndEntries()
      .map((object) => object.uuid.uuid)
      .toSet();

  Set<String> recordUuids(KdbxFile file) =>
      file.body.deletedObjects.map((record) => record.uuid.uuid).toSet();

  /// What both copies must agree on once they merged each other, and what no
  /// file may hold: a uuid that is live and deleted at once.
  void expectConverged(KdbxFile a, KdbxFile b) {
    expect(liveUuids(a), liveUuids(b), reason: 'live objects');
    expect(recordUuids(a), recordUuids(b), reason: 'deletion records');
    for (final file in [a, b]) {
      expect(
        liveUuids(file).intersection(recordUuids(file)),
        isEmpty,
        reason: 'live and deleted at once',
      );
    }
  }

  /// Merges each copy into a fresh read of the other's saved state, so that
  /// both see the other as it was before either merge.
  Future<(KdbxFile, KdbxFile, MergeContext, MergeContext)> crossMerge(
    KdbxFile a,
    KdbxFile b,
  ) async {
    a = await testUtil.saveAndRead(a);
    b = await testUtil.saveAndRead(b);
    final intoA = await testUtil.saveAndRead(a);
    final intoB = await testUtil.saveAndRead(b);
    proceedSeconds(10);
    final mergedA = intoA.merge(b);
    final mergedB = intoB.merge(a);
    return (intoA, intoB, mergedA, mergedB);
  }

  group('deletion records', () {
    test(
      'of a group and everything in it share one time',
      () async {
        // a clock that moves on every time it is read, the way a real one
        // can cross a second while a group is being deleted.
        var ticking = DateTime.utc(2020);
        await withClock(
          Clock(() => ticking = ticking.add(const Duration(seconds: 1))),
          () async {
            final file = await createBase();
            file.deletePermanently(groupNamed(file, 'group')!);
            final times = file.body.deletedObjects
                .map((record) => record.deletionTime.get())
                .toSet();
            expect(file.body.deletedObjects, hasLength(3));
            expect(times, hasLength(1));
          },
        );
      },
    );

    test(
      'taken over from the other copy keep its deletion time',
      () async => await withClock(fakeClock, () async {
        final (a, bBase) = await twoCopies();
        var b = bBase;
        proceedSeconds(10);
        b.deletePermanently(entryNamed(b, 'user')!);
        final deletedAt = b.body.deletedObjects.single.deletionTime.get();
        b = await testUtil.saveAndRead(b);

        proceedSeconds(100);
        final merge = a.merge(b);

        expect(a.body.deletedObjects.single.deletionTime.get(), deletedAt);
        final event = merge.events.single as MergeObjectDeleted;
        expect(event.deletionTime, deletedAt);
      }),
    );
  });

  group('a deletion on one side', () {
    test(
      'removes an entry the other side did not change',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        a.deletePermanently(entryNamed(a, 'user')!);

        final (intoA, intoB, _, _) = await crossMerge(a, b);

        expect(entryNamed(intoA, 'user'), isNull);
        expect(entryNamed(intoB, 'user'), isNull);
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'loses against a later edit on the other side',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        a.deletePermanently(entryNamed(a, 'user')!);
        proceedSeconds(10);
        setPassword(entryNamed(b, 'user')!, 'edited later');

        final (intoA, intoB, _, _) = await crossMerge(a, b);

        // the edit used to be removed by the older deletion.
        for (final file in [intoA, intoB]) {
          expect(
            entryNamed(
              file,
              'user',
            )?.getString(KdbxKeyCommon.PASSWORD)?.getText(),
            'edited later',
          );
        }
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'wins against an earlier edit on the other side',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        setPassword(entryNamed(b, 'user')!, 'edited earlier');
        proceedSeconds(10);
        a.deletePermanently(entryNamed(a, 'user')!);

        final (intoA, intoB, _, _) = await crossMerge(a, b);

        expect(entryNamed(intoA, 'user'), isNull);
        expect(entryNamed(intoB, 'user'), isNull);
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'loses against an edit in the same second',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        a.deletePermanently(entryNamed(a, 'user')!);
        setPassword(entryNamed(b, 'user')!, 'same second');

        final (intoA, intoB, _, _) = await crossMerge(a, b);

        expect(entryNamed(intoA, 'user'), isNotNull);
        expect(entryNamed(intoB, 'user'), isNotNull);
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'loses against a later move on the other side',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        a.deletePermanently(entryNamed(a, 'user')!);
        proceedSeconds(10);
        // a move is a decision about the entry too - for one thing, it is
        // how an entry comes back out of the recycle bin.
        b.move(entryNamed(b, 'user')!, groupNamed(b, 'group')!);

        final (intoA, intoB, _, _) = await crossMerge(a, b);

        for (final file in [intoA, intoB]) {
          expect(entryNamed(file, 'user')?.parent?.name.get(), 'group');
        }
        expectConverged(intoA, intoB);
      }),
    );
  });

  group('a group deleted on one side', () {
    test(
      'keeps what the other side put into it since',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        testUtil.createEntry(b, groupNamed(b, 'group')!, 'mine', 'new');
        proceedSeconds(10);
        a.deletePermanently(groupNamed(a, 'group')!);

        final (intoA, intoB, mergedA, mergedB) = await crossMerge(a, b);

        // The group stays for the entry `a` never knew of, and what `a`
        // did know of in it goes. The new entry used to be removed with
        // the group, silently.
        for (final file in [intoA, intoB]) {
          final group = groupNamed(file, 'group');
          expect(group, isNotNull);
          expect(group!.entries.map((e) => e.debugLabel()), ['mine']);
        }
        expect(mergedA.warnings, isEmpty);
        expect(mergedB.warnings, isEmpty);
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'keeps an entry the other side moved into it since',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        b.move(entryNamed(b, 'user')!, groupNamed(b, 'group')!);
        proceedSeconds(10);
        a.deletePermanently(groupNamed(a, 'group')!);

        final (intoA, intoB, _, _) = await crossMerge(a, b);

        for (final file in [intoA, intoB]) {
          expect(entryNamed(file, 'user')?.parent?.name.get(), 'group');
          expect(entryNamed(file, 'first'), isNull);
        }
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'with nothing newer in it goes entirely',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await twoCopies();
        proceedSeconds(10);
        a.deletePermanently(groupNamed(a, 'group')!);

        final (intoA, intoB, _, _) = await crossMerge(a, b);

        expect(groupNamed(intoA, 'group'), isNull);
        expect(groupNamed(intoB, 'group'), isNull);
        expect(intoB.body.rootGroup.getAllEntries(), hasLength(1));
        expectConverged(intoA, intoB);
      }),
    );
  });

  group('a copy that is merely behind', () {
    test(
      'does not bring back what was deleted here, nor dirty the file',
      () async => await withClock(fakeClock, () async {
        var (a, b) = await twoCopies();
        proceedSeconds(10);
        a.deletePermanently(entryNamed(a, 'user')!);
        a.deletePermanently(groupNamed(a, 'group')!);
        a = await testUtil.saveAndRead(a);

        proceedSeconds(10);
        final merge = a.merge(b);

        // "emptied the trash offline, then opened the app": the other copy
        // still has everything, unchanged since. It used to all come back,
        // live and deleted at once.
        expect(a.body.rootGroup.getAllEntries(), isEmpty);
        expect(groupNamed(a, 'group'), isNull);
        expect(recordUuids(a), hasLength(4));
        expect(merge.totalChanges(), 0);
        expect(merge.events, isEmpty);
        expect(a.isDirty, isFalse);
      }),
    );
  });

  group('an object a merge removed', () {
    test(
      'refuses an edit, rather than accepting one that is never saved',
      () async => await withClock(fakeClock, () async {
        final (a, bBase) = await twoCopies();
        var b = bBase;
        final open = entryNamed(a, 'user')!;
        proceedSeconds(10);
        b.deletePermanently(entryNamed(b, 'user')!);
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        a.merge(b);

        expect(
          () => setPassword(open, 'too late'),
          throwsA(
            isA<KdbxObjectRemovedException>().having(
              (e) => e.object,
              'object',
              same(open),
            ),
          ),
        );
      }),
    );

    test(
      'can be restored, and stays restored through the next merge',
      () async => await withClock(fakeClock, () async {
        var (a, b) = await twoCopies();
        final open = entryNamed(a, 'user')!;
        proceedSeconds(10);
        b.deletePermanently(entryNamed(b, 'user')!);
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        a.merge(b);
        a.restore(open);
        setPassword(open, 'restored');

        expect(open.parent, same(a.body.rootGroup));
        expect(recordUuids(a), isNot(contains(open.uuid.uuid)));

        a = await testUtil.saveAndRead(a);
        final (intoA, intoB, _, _) = await crossMerge(a, b);
        for (final file in [intoA, intoB]) {
          expect(
            entryNamed(
              file,
              'user',
            )?.getString(KdbxKeyCommon.PASSWORD)?.getText(),
            'restored',
          );
        }
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'restored in the second it was deleted in is still newer',
      () async => await withClock(fakeClock, () async {
        var (a, b) = await twoCopies();
        final open = entryNamed(a, 'user')!;
        proceedSeconds(10);
        b.deletePermanently(entryNamed(b, 'user')!);
        b = await testUtil.saveAndRead(b);

        // no time passes: restoring must still beat the deletion.
        a.merge(b);
        a.restore(open);

        final (intoA, intoB, _, _) = await crossMerge(a, b);
        expect(entryNamed(intoA, 'user'), isNotNull);
        expect(entryNamed(intoB, 'user'), isNotNull);
        expectConverged(intoA, intoB);
      }),
    );

    test(
      'is not restored a second time once a later merge brought it back',
      () async => await withClock(fakeClock, () async {
        final (a, bBase) = await twoCopies();
        var b = bBase;
        final c = await testUtil.saveAndRead(a);
        final open = entryNamed(a, 'user')!;
        proceedSeconds(10);
        b.deletePermanently(entryNamed(b, 'user')!);
        b = await testUtil.saveAndRead(b);
        proceedSeconds(10);
        a.merge(b);

        // a third copy changed it after the deletion, so it comes back - as
        // a new object, while the screen still holds the removed one.
        proceedSeconds(10);
        setPassword(entryNamed(c, 'user')!, 'edited elsewhere');
        a.merge(await testUtil.saveAndRead(c));
        final back = entryNamed(a, 'user');
        expect(back, isNot(same(open)));

        // into the group it is in again, and into another one: either way
        // it used to end up live twice under one uuid.
        for (final into in [null, groupNamed(a, 'group')]) {
          expect(
            () => a.restore(open, into: into),
            throwsA(isA<KdbxDuplicateUuidException>()),
          );
        }
        expect(open.parent, isNull);
        expect(open.isRemovedByMerge, isTrue);
        expect(a.findDuplicateUuidObjects(), isEmpty);
        expect(entryNamed(a, 'user'), same(back));
      }),
    );
  });
}
