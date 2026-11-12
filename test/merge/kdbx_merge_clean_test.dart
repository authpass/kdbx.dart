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

  /// A saved file with two entries, one in a sub group, and a recycle bin
  /// holding a third - so a merge has every kind of object to walk past.
  Future<KdbxFile> createBase() async {
    final file = testUtil.createEmptyFile();
    testUtil.createEntry(file, file.body.rootGroup, 'user', 'base');
    final group = file.createGroup(parent: file.body.rootGroup, name: 'group');
    testUtil.createEntry(file, group, 'other', 'base');
    final trashed = testUtil.createEntry(
      file,
      file.body.rootGroup,
      'trashed',
      'base',
    );
    file.deleteEntry(trashed);
    proceedSeconds(10);
    return await testUtil.saveAndRead(file);
  }

  KdbxEntry entryNamed(KdbxFile file, String user) =>
      file.body.rootGroup.getAllEntries().firstWhere(
        (entry) => entry.getString(KdbxKeyCommon.USER_NAME)?.getText() == user,
      );

  void setPassword(KdbxFile file, String user, String value) => entryNamed(
    file,
    user,
  ).setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value));

  group('a merge that changes nothing', () {
    test(
      'leaves the file clean and reports no changes',
      () async => await withClock(fakeClock, () async {
        final a = await createBase();
        final b = await testUtil.saveAndRead(a);

        proceedSeconds(10);
        final merge = a.merge(b);

        expect(merge.changes, isEmpty);
        expect(merge.totalChanges(), 0);
        expect(a.isDirty, isFalse);
        expect(a.dirtyObjects, isEmpty);
      }),
    );

    test(
      'reports no changes for deletions both copies already have',
      () async => await withClock(fakeClock, () async {
        var a = await createBase();
        proceedSeconds(10);
        a.deletePermanently(entryNamed(a, 'other'));
        a = await testUtil.saveAndRead(a);
        final b = await testUtil.saveAndRead(a);
        expect(a.body.deletedObjects, hasLength(1));

        proceedSeconds(10);
        final merge = a.merge(b);

        // `totalChanges` used to count every deletion record in the file,
        // so a file with any history of deletions never reported a no-op.
        expect(merge.totalChanges(), 0);
        expect(a.isDirty, isFalse);
      }),
    );

    test(
      'leaves the copy that made the change clean when it merges it back',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(b, 'user', 'from b');
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        a.merge(b);
        a = await testUtil.saveAndRead(a);

        // `b` made the change and `a` only took it over, so `b` has nothing
        // to learn from `a`. A merge that dirtied `b` anyway would make every
        // cold start that saw a remote change write it straight back.
        proceedSeconds(10);
        final merge = b.merge(a);

        expect(merge.changes, isEmpty);
        expect(merge.totalChanges(), 0);
        expect(b.isDirty, isFalse);
      }),
    );

    test(
      'stays clean through repeated rounds once both copies agree',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(a, 'user', 'from a');
        setPassword(b, 'other', 'from b');
        a = await testUtil.saveAndRead(a);
        b = await testUtil.saveAndRead(b);

        // one round to exchange both edits...
        proceedSeconds(10);
        a.merge(b);
        a = await testUtil.saveAndRead(a);
        proceedSeconds(10);
        b.merge(a);
        b = await testUtil.saveAndRead(b);

        // ...after which neither has anything left to take from the other.
        for (var round = 0; round < 3; round++) {
          proceedSeconds(10);
          final intoA = a.merge(b);
          expect(intoA.totalChanges(), 0, reason: 'round $round into a');
          expect(a.isDirty, isFalse, reason: 'round $round into a');
          proceedSeconds(10);
          final intoB = b.merge(a);
          expect(intoB.totalChanges(), 0, reason: 'round $round into b');
          expect(b.isDirty, isFalse, reason: 'round $round into b');
        }
      }),
    );
  });

  group('a merge that changes something', () {
    test(
      'marks the file dirty and counts the change',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(b, 'user', 'from b');
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final merge = a.merge(b);

        expect(merge.totalChanges(), greaterThan(0));
        expect(a.isDirty, isTrue);
      }),
    );

    test(
      'counts a deletion it takes over',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        b.deletePermanently(entryNamed(b, 'other'));
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final merge = a.merge(b);

        expect(merge.totalChanges(), greaterThan(0));
        expect(a.isDirty, isTrue);
      }),
    );
  });
}
