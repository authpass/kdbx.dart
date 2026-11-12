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

  /// A saved file with one entry in the root group and one group.
  Future<KdbxFile> createBase({int? historyMaxItems}) async {
    final file = testUtil.createEmptyFile();
    if (historyMaxItems != null) {
      file.body.meta.historyMaxItems.set(historyMaxItems);
    }
    testUtil.createEntry(file, file.body.rootGroup, 'user', 'base');
    file.createGroup(parent: file.body.rootGroup, name: 'group');
    proceedSeconds(10);
    return await testUtil.saveAndRead(file);
  }

  KdbxEntry theEntry(KdbxFile file) =>
      file.body.rootGroup.getAllEntries().single;

  KdbxGroup theGroup(KdbxFile file) => file.body.rootGroup.groups.single;

  String? password(KdbxEntry entry) =>
      entry.getString(KdbxKeyCommon.PASSWORD)?.getText();

  void setPassword(KdbxEntry entry, String value) =>
      entry.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value));

  Set<String?> historyPasswords(KdbxEntry entry) =>
      entry.history.map(password).toSet();

  group('same-second edits on both sides', () {
    /// Copies of one saved file, each with its own password set in the same
    /// second, and saved.
    Future<(KdbxFile, KdbxFile)> conflictingCopies() async {
      final base = await createBase();
      var a = await testUtil.saveAndRead(base);
      var b = await testUtil.saveAndRead(base);
      proceedSeconds(10);
      setPassword(theEntry(a), 'from a');
      setPassword(theEntry(b), 'from b');
      a = await testUtil.saveAndRead(a);
      b = await testUtil.saveAndRead(b);
      expect(
        theEntry(a).times.lastModificationTime.get(),
        theEntry(b).times.lastModificationTime.get(),
        reason: 'the premise: neither edit is newer than the other',
      );
      return (a, b);
    }

    test(
      'pick the same winner from both directions',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await conflictingCopies();
        final intoA = await testUtil.saveAndRead(a);
        final intoB = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        intoA.merge(b);
        intoB.merge(a);

        // Each used to keep its own value, with no change, no warning and no
        // revision of the other - and every later merge agreed.
        expect(password(theEntry(intoA)), password(theEntry(intoB)));
        expect(password(theEntry(intoA)), isIn(['from a', 'from b']));
      }),
    );

    test(
      'keep the losing edit as a revision on both sides',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await conflictingCopies();
        final intoA = await testUtil.saveAndRead(a);
        final intoB = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        intoA.merge(b);
        intoB.merge(a);

        for (final file in [intoA, intoB]) {
          final entry = theEntry(file);
          final loser = password(entry) == 'from a' ? 'from b' : 'from a';
          expect(historyPasswords(entry), contains(loser));
          expect(file.isDirty, isTrue);
        }
      }),
    );

    test(
      'report which side was kept, and that content decided it',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await conflictingCopies();
        final intoA = await testUtil.saveAndRead(a);
        final intoB = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final eventsA = intoA.merge(b).events;
        final eventsB = intoB.merge(a).events;

        final aWon = password(theEntry(intoA)) == 'from a';
        final (winner, loser) = aWon ? (eventsA, eventsB) : (eventsB, eventsA);
        expect(winner, [
          isA<MergeLocalVersionKept>().having(
            (e) => e.decidedByContent,
            'decidedByContent',
            isTrue,
          ),
        ]);
        expect(loser, [
          isA<MergeObjectUpdated>().having(
            (e) => e.decidedByContent,
            'decidedByContent',
            isTrue,
          ),
        ]);
      }),
    );

    test(
      'converge, after which merging changes nothing',
      () async => await withClock(fakeClock, () async {
        var (a, b) = await conflictingCopies();

        proceedSeconds(10);
        a.merge(b);
        a = await testUtil.saveAndRead(a);
        proceedSeconds(10);
        b.merge(a);
        b = await testUtil.saveAndRead(b);

        expect(password(theEntry(a)), password(theEntry(b)));
        expect(historyPasswords(theEntry(a)), historyPasswords(theEntry(b)));
        expect(theEntry(a).history, hasLength(theEntry(b).history.length));
        for (var round = 0; round < 2; round++) {
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

    test(
      'of a group pick the same winner from both directions',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);
        proceedSeconds(10);
        theGroup(a).name.set('from a');
        theGroup(b).name.set('from b');
        a = await testUtil.saveAndRead(a);
        b = await testUtil.saveAndRead(b);
        final intoA = await testUtil.saveAndRead(a);
        final intoB = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        intoA.merge(b);
        intoB.merge(a);

        expect(theGroup(intoA).name.get(), theGroup(intoB).name.get());
      }),
    );
  });

  group('editing again within the second of the last save', () {
    test(
      'is still newer than the saved version',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var writer = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(theEntry(writer), 'first');
        writer = await testUtil.saveAndRead(writer);
        // a device syncs this version...
        final reader = await testUtil.saveAndRead(writer);

        // ...and the writer edits again, still in the same second.
        setPassword(theEntry(writer), 'second');
        writer = await testUtil.saveAndRead(writer);

        expect(
          theEntry(writer).times.lastModificationTime.get(),
          isNot(theEntry(reader).times.lastModificationTime.get()),
        );
        proceedSeconds(10);
        reader.merge(writer);
        // the reader used to keep 'first': the same second, so not newer.
        expect(password(theEntry(reader)), 'second');
      }),
    );

    test(
      'does not move the time forward once per change',
      () async => await withClock(fakeClock, () async {
        var file = await createBase();
        proceedSeconds(10);
        setPassword(theEntry(file), 'saved');
        file = await testUtil.saveAndRead(file);
        final savedAt = theEntry(file).times.lastModificationTime.get()!;

        // still unsaved, so these are one version, not three: only the first
        // change has a saved version to be newer than.
        final entry = theEntry(file);
        setPassword(entry, 'one');
        setPassword(entry, 'two');
        entry.setString(KdbxKeyCommon.URL, PlainValue('https://example.com'));

        expect(
          entry.times.lastModificationTime.get(),
          savedAt.add(const Duration(seconds: 1)),
        );
      }),
    );

    test(
      'is still newer for a group',
      () async => await withClock(fakeClock, () async {
        var file = await createBase();
        proceedSeconds(10);
        theGroup(file).name.set('first');
        file = await testUtil.saveAndRead(file);
        final savedAt = theGroup(file).times.lastModificationTime.get()!;

        theGroup(file).name.set('second');

        expect(
          theGroup(file).times.lastModificationTime.get(),
          savedAt.add(const Duration(seconds: 1)),
        );
      }),
    );

    test(
      'is stamped with the clock once that has moved on',
      () async => await withClock(fakeClock, () async {
        var file = await createBase();
        proceedSeconds(10);
        setPassword(theEntry(file), 'saved');
        file = await testUtil.saveAndRead(file);

        proceedSeconds(10);
        setPassword(theEntry(file), 'later');

        expect(theEntry(file).times.lastModificationTime.get(), now.toUtc());
      }),
    );
  });

  group('a version descending from the other', () {
    test(
      'wins even when its clock put it earlier',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(theEntry(a), 'from a');
        a = await testUtil.saveAndRead(a);
        var b = await testUtil.saveAndRead(a);

        // `b` edits on top of `a`'s version, but is written by something
        // with a clock five seconds behind, which does not stamp edits after
        // the version they replace.
        setPassword(theEntry(b), 'from b, later');
        theEntry(b).times.lastModificationTime.set(
          now.subtract(const Duration(seconds: 5)).toUtc(),
        );
        b = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        final intoA = await testUtil.saveAndRead(a)
          ..merge(b);
        final intoB = await testUtil.saveAndRead(b)
          ..merge(a);

        // `b` holds `a`'s version in its history, so `b`'s edit came after
        // it, whatever the clocks say.
        expect(password(theEntry(intoA)), 'from b, later');
        expect(password(theEntry(intoB)), 'from b, later');
        expect(intoB.isDirty, isFalse);
      }),
    );
  });

  group('history revisions', () {
    /// Two copies whose entries hold the same current version, but each a
    /// different revision from the same second.
    Future<(KdbxFile, KdbxFile)> sameSecondRevisions({
      int? historyMaxItems,
    }) async {
      final base = await createBase(historyMaxItems: historyMaxItems);
      var a = await testUtil.saveAndRead(base);
      var b = await testUtil.saveAndRead(base);
      proceedSeconds(10);
      setPassword(theEntry(a), 'p');
      setPassword(theEntry(b), 'q');
      a = await testUtil.saveAndRead(a);
      b = await testUtil.saveAndRead(b);
      proceedSeconds(10);
      setPassword(theEntry(a), 'final');
      setPassword(theEntry(b), 'final');
      a = await testUtil.saveAndRead(a);
      b = await testUtil.saveAndRead(b);
      return (a, b);
    }

    test(
      'from the same second but with different content are both kept',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await sameSecondRevisions();

        proceedSeconds(10);
        a.merge(b);
        b.merge(a);

        // a revision used to be recognised by its time alone, so `q` looked
        // like `p` and was never brought over.
        expect(historyPasswords(theEntry(a)), containsAll(['p', 'q']));
        expect(historyPasswords(theEntry(b)), containsAll(['p', 'q']));
      }),
    );

    test(
      'from the same second are pruned alike on both sides',
      () async => await withClock(fakeClock, () async {
        final (a, b) = await sameSecondRevisions(historyMaxItems: 1);
        expect(historyPasswords(theEntry(a)), {'p'});
        expect(historyPasswords(theEntry(b)), {'q'});

        proceedSeconds(10);
        final intoA = await testUtil.saveAndRead(a)
          ..merge(b);
        final intoB = await testUtil.saveAndRead(b)
          ..merge(a);

        // Each prune used to drop whichever came first in its own list, which
        // is its own revision on one side and the other's on the other - so
        // the two kept different revisions and traded them on every sync.
        expect(theEntry(intoA).history, hasLength(1));
        expect(
          historyPasswords(theEntry(intoA)),
          historyPasswords(theEntry(intoB)),
        );
      }),
    );
  });
}
