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

  /// A saved file with one entry in the root group and two empty groups.
  Future<KdbxFile> createBase() async {
    final file = testUtil.createEmptyFile();
    testUtil.createEntry(file, file.body.rootGroup, 'user', 'base');
    file.createGroup(parent: file.body.rootGroup, name: 'group a');
    file.createGroup(parent: file.body.rootGroup, name: 'group b');
    proceedSeconds(10);
    return await testUtil.saveAndRead(file);
  }

  KdbxEntry theEntry(KdbxFile file) =>
      file.body.rootGroup.getAllEntries().single;

  KdbxGroup groupNamed(KdbxFile file, String name) => file.body.rootGroup
      .getAllGroups()
      .firstWhere((group) => group.name.get() == name);

  void setPassword(KdbxEntry entry, String value) =>
      entry.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value));

  group('merge events', () {
    test(
      'a merge that changes nothing reports no events',
      () async => await withClock(fakeClock, () async {
        final a = await createBase();
        final b = await testUtil.saveAndRead(a);

        proceedSeconds(10);
        expect(a.merge(b).events, isEmpty);
      }),
    );

    test(
      'taking the other copy\'s newer entry reports an update',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(theEntry(b), 'from b');
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final events = a.merge(b).events;

        expect(events, hasLength(1));
        final event = events.single as MergeObjectUpdated;
        expect(event.object, same(theEntry(a)));
        expect(event.uuid, theEntry(a).uuid);
        expect(event.keptUnsavedEdit, isFalse);
      }),
    );

    test(
      'an update over an unsaved local edit says the edit was kept',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(theEntry(a), 'unsaved in a');
        proceedSeconds(10);
        setPassword(theEntry(b), 'newer in b');
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final event = a.merge(b).events.single as MergeObjectUpdated;

        expect(event.object, same(theEntry(a)));
        expect(event.keptUnsavedEdit, isTrue);
      }),
    );

    test(
      'keeping our newer entry over a change we never saw reports it',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        // both edit; `a` later, so `a` wins and `b`'s change goes to history.
        proceedSeconds(10);
        setPassword(theEntry(b), 'from b');
        b = await testUtil.saveAndRead(b);
        proceedSeconds(10);
        setPassword(theEntry(a), 'from a');

        proceedSeconds(10);
        final event = a.merge(b).events.single as MergeLocalVersionKept;

        expect(event.object, same(theEntry(a)));
      }),
    );

    test(
      'keeping our newer entry over an older version we had reports nothing',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);
        final staleB = await testUtil.saveAndRead(base);

        // only `a` edits; `b` is simply behind, which is no news to `a`.
        proceedSeconds(10);
        setPassword(theEntry(a), 'from a');
        a = await testUtil.saveAndRead(a);

        proceedSeconds(10);
        expect(a.merge(staleB).events, isEmpty);
      }),
    );

    test(
      'keeping our newer entry over a version we had and pruned reports '
      'nothing',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);
        final staleB = await testUtil.saveAndRead(base);

        // `a` edits more often than its history may hold, so the state `b`
        // is still in is gone from it. `b` is behind all the same.
        a.body.meta.historyMaxItems.set(2);
        for (var i = 0; i < 4; i++) {
          proceedSeconds(10);
          setPassword(theEntry(a), 'from a $i');
          a = await testUtil.saveAndRead(a);
        }
        expect(theEntry(a).history, hasLength(2));

        proceedSeconds(10);
        expect(a.merge(staleB).events, isEmpty);
        // their state came back and was pruned again at once, so there is
        // no revision an event could point the user to.
        expect(theEntry(a).history, hasLength(2));
        expect(
          theEntry(a).history.map(
            (revision) => revision.times.lastModificationTime.get(),
          ),
          isNot(contains(theEntry(staleB).times.lastModificationTime.get())),
        );

        // and it stays quiet for as long as `b` stays behind.
        a = await testUtil.saveAndRead(a);
        proceedSeconds(10);
        expect(a.merge(staleB).events, isEmpty);
      }),
    );

    test(
      'a group created in the other copy brings an event for everything in it',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        final created = b.createGroup(
          parent: groupNamed(b, 'group a'),
          name: 'new',
        );
        final createdSub = b.createGroup(parent: created, name: 'new sub');
        final createdEntry = testUtil.createEntry(b, createdSub, 'deep', 'one');
        b = await testUtil.saveAndRead(b);
        // an edit, so that the entry arrives with a history revision - which
        // is part of the entry, not an update of it.
        proceedSeconds(10);
        setPassword(
          b.body.rootGroup.getAllEntries().firstWhere(
            (entry) => entry.uuid == createdEntry.uuid,
          ),
          'two',
        );
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final events = a.merge(b).events;

        expect(events, everyElement(isA<MergeObjectAdded>()));
        expect(events.map((event) => event.uuid), [
          created.uuid,
          createdSub.uuid,
          createdEntry.uuid,
        ]);
        expect(events[0].object, same(groupNamed(a, 'new')));
        expect(events[1].object, same(groupNamed(a, 'new sub')));
        expect(events[2].object.parent, same(groupNamed(a, 'new sub')));
        expect((events[2].object as KdbxEntry).history, hasLength(1));

        // nothing of it is news a second time.
        expect(a.merge(b).events, isEmpty);
      }),
    );

    test(
      'taking a renamed group reports an update',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        groupNamed(b, 'group a').name.set('renamed');
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final event = a.merge(b).events.single as MergeObjectUpdated;

        expect(event.object, same(groupNamed(a, 'renamed')));
        expect(event.keptUnsavedEdit, isFalse);
      }),
    );

    test(
      'an entry created in the other copy is reported as added',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        final created = testUtil.createEntry(
          b,
          groupNamed(b, 'group a'),
          'new',
          'pass',
        );
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final event = a.merge(b).events.single as MergeObjectAdded;

        expect(event.uuid, created.uuid);
        expect(event.object, isA<KdbxEntry>());
        expect(event.object.parent, same(groupNamed(a, 'group a')));
      }),
    );

    test(
      'a move in the other copy is reported with both groups',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        b.move(theEntry(b), groupNamed(b, 'group b'));
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final event = a.merge(b).events.single as MergeObjectMoved;

        expect(event.object, same(theEntry(a)));
        expect(event.from, same(a.body.rootGroup));
        expect(event.to, same(groupNamed(a, 'group b')));
      }),
    );

    test(
      'an edit and a move in the other copy are reported separately',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        b.move(theEntry(b), groupNamed(b, 'group b'));
        setPassword(theEntry(b), 'from b');
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final events = a.merge(b).events;

        expect(events.whereType<MergeObjectMoved>(), hasLength(1));
        expect(events.whereType<MergeObjectUpdated>(), hasLength(1));
        expect(events, hasLength(2));
        expect(events.map((event) => event.object).toSet(), {theEntry(a)});
      }),
    );

    test(
      'a deletion in the other copy is reported with the removed object',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);
        final doomed = theEntry(a);

        proceedSeconds(10);
        b.deletePermanently(theEntry(b));
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final event = a.merge(b).events.single as MergeObjectDeleted;

        // the object has left the tree, but a UI can still name what went.
        expect(event.object, same(doomed));
        expect(event.object.parent, isNull);
        expect(event.deletionTime, isNotNull);
      }),
    );

    test(
      'a deleted group brings an event for everything that was in it',
      () async => await withClock(fakeClock, () async {
        var base = await createBase();
        final sub = base.createGroup(
          parent: groupNamed(base, 'group a'),
          name: 'sub',
        );
        testUtil.createEntry(base, sub, 'deep', 'pass');
        testUtil.createEntry(base, groupNamed(base, 'group a'), 'flat', 'pass');
        base = await testUtil.saveAndRead(base);
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);
        final doomed = groupNamed(
          a,
          'group a',
        ).getAllGroupsAndEntries().toSet();
        expect(doomed, hasLength(4));

        proceedSeconds(10);
        b.deletePermanently(groupNamed(b, 'group a'));
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final mergeContext = a.merge(b);
        final events = mergeContext.events;

        expect(events, everyElement(isA<MergeObjectDeleted>()));
        expect(events, hasLength(4));
        expect(events.map((event) => event.object).toSet(), doomed);
        expect(mergeContext.warnings, isEmpty);
        // every one of them is detached, the groups from their children as
        // well: a removed group arrives empty.
        for (final event in events) {
          expect(event.object.parent, isNull);
          final object = event.object;
          if (object is KdbxGroup) {
            expect(object.groups, isEmpty);
            expect(object.entries, isEmpty);
          }
        }
        expect(a.body.rootGroup.getAllEntries().map((e) => e.debugLabel()), [
          'user',
        ]);
      }),
    );

    test(
      'an entry the other copy put in the recycle bin is reported as a move',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        b.deleteEntry(theEntry(b));
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final events = a.merge(b).events;

        // `b` had to create its recycle bin first, which is a group like
        // any other.
        expect(events, hasLength(2));
        final added = events[0] as MergeObjectAdded;
        final moved = events[1] as MergeObjectMoved;
        expect(added.uuid, a.body.meta.recycleBinUUID.get());
        expect(moved.object, same(theEntry(a)));
        expect(moved.from, same(a.body.rootGroup));
        expect(moved.to, same(added.object));
        expect(a.recycleBin, same(moved.to));
        expect(theEntry(a).isInRecycleBin(), isTrue);
      }),
    );

    test(
      'the event list cannot be changed by a caller',
      () async => await withClock(fakeClock, () async {
        final a = await createBase();
        final b = await testUtil.saveAndRead(a);

        final events = a.merge(b).events;
        expect(events.clear, throwsUnsupportedError);
      }),
    );

    test(
      'an entry a merge brought in is not mistaken for an unsaved edit',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        // `b` creates an entry, `a` takes it in and does not save...
        proceedSeconds(10);
        final created = testUtil.createEntry(
          b,
          b.body.rootGroup,
          'new',
          'first',
        );
        b = await testUtil.saveAndRead(b);
        proceedSeconds(10);
        a.merge(b);
        final imported = a.body.rootGroup.entries.firstWhere(
          (entry) => entry.uuid == created.uuid,
        );
        expect(imported.isDirty, isTrue);

        // ...and `b` edits it again. Nothing `a` holds is the user's work.
        proceedSeconds(10);
        setPassword(
          b.body.rootGroup.entries.firstWhere(
            (entry) => entry.uuid == created.uuid,
          ),
          'second',
        );
        b = await testUtil.saveAndRead(b);
        proceedSeconds(10);
        final event = a.merge(b).events.single as MergeObjectUpdated;

        expect(event.object, same(imported));
        expect(event.keptUnsavedEdit, isFalse);
      }),
    );

    test(
      'a local edit to an entry a merge brought in keeps that version',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        final created = testUtil.createEntry(
          b,
          b.body.rootGroup,
          'new',
          'from b',
        );
        b = await testUtil.saveAndRead(b);
        proceedSeconds(10);
        a.merge(b);
        final imported = a.body.rootGroup.entries.firstWhere(
          (entry) => entry.uuid == created.uuid,
        );

        // edited before `a` is saved: the version `b` made is a state of its
        // own, the same as one a merge takes over.
        proceedSeconds(10);
        setPassword(imported, 'edited in a');

        expect(
          imported.history.map(
            (revision) => revision.getString(KdbxKeyCommon.PASSWORD)?.getText(),
          ),
          ['from b'],
        );
      }),
    );

    test(
      'a group only collapsed or scrolled elsewhere is not reported',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        final group = groupNamed(b, 'group a');
        group.expanded.set(!(group.expanded.get() ?? true));
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final merge = a.merge(b);

        // the merge does take it over - it is newer - but there is nothing
        // to tell a user about.
        expect(
          groupNamed(a, 'group a').expanded.get(),
          groupNamed(b, 'group a').expanded.get(),
        );
        expect(merge.events, isEmpty);
      }),
    );
  });
}
