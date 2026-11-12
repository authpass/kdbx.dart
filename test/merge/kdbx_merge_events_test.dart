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
      'the event list cannot be changed by a caller',
      () async => await withClock(fakeClock, () async {
        final a = await createBase();
        final b = await testUtil.saveAndRead(a);

        final events = a.merge(b).events;
        expect(events.clear, throwsUnsupportedError);
      }),
    );
  });
}
