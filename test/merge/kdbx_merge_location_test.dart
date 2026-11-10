import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';

import '../internal/test_utils.dart';

final _logger = Logger('kdbx_merge_location_test');

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

  /// A file with two spare groups and one entry in the root group.
  Future<KdbxFile> createFileWithGroups() async {
    final file = testUtil.createEmptyFile();
    testUtil.createEntry(file, file.body.rootGroup, 'user', 'pass');
    file.createGroup(parent: file.body.rootGroup, name: 'target a');
    file.createGroup(parent: file.body.rootGroup, name: 'target b');
    proceedSeconds(10);
    return await testUtil.saveAndRead(file);
  }

  KdbxGroup groupByName(KdbxFile file, String name) => file.body.rootGroup
      .getAllGroups()
      .firstWhere((group) => group.name.get() == name);

  KdbxEntry theEntry(KdbxFile file) => file.body.rootGroup
      .getAllGroupsAndEntries()
      .whereType<KdbxEntry>()
      .single;

  void logLocation(String label, KdbxEntry entry) {
    _logger.info(
      '$label: parent=${entry.parent!.name.get()} '
      'locationChanged=${entry.times.locationChanged.get()} '
      'lastModified=${entry.times.lastModificationTime.get()}',
    );
  }

  group('locationChanged during merge', () {
    test(
      'a newer incoming edit does not reset our locationChanged',
      () async => await withClock(fakeClock, () async {
        final base = await createFileWithGroups();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        // `a` moves the entry.
        proceedSeconds(10);
        final aMovedAt = clock.now().toUtc();
        a.move(theEntry(a), groupByName(a, 'target a'));

        // `b` edits a field afterwards, but never moves the entry.
        proceedSeconds(10);
        theEntry(
          b,
        ).setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('new'));

        logLocation('a before merge', theEntry(a));
        logLocation('b before merge', theEntry(b));
        a.merge(await testUtil.saveAndRead(b));
        logLocation('a after merge', theEntry(a));

        // The entry stays where `a` put it...
        expect(theEntry(a).parent!.name.get(), 'target a');
        // ...so the recorded location time has to be the time of that move,
        // not the time `b` recorded for a location it never changed.
        expect(theEntry(a).times.locationChanged.get(), aMovedAt);
      }),
    );

    test(
      'a stale locationChanged does not move the entry back on a later merge',
      () async => await withClock(fakeClock, () async {
        final base = await createFileWithGroups();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);
        final c = await testUtil.saveAndRead(base);

        // `c` moves the entry to 'target b'.
        proceedSeconds(10);
        c.move(theEntry(c), groupByName(c, 'target b'));

        // `a` moves the entry to 'target a' -- later, so this move wins.
        proceedSeconds(10);
        a.move(theEntry(a), groupByName(a, 'target a'));

        // `b` only edits a field, later still, and never moves the entry.
        proceedSeconds(10);
        theEntry(
          b,
        ).setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('new'));

        a.merge(await testUtil.saveAndRead(b));
        logLocation('a after merging b', theEntry(a));
        expect(theEntry(a).parent!.name.get(), 'target a');

        a.merge(await testUtil.saveAndRead(c));
        logLocation('a after merging c', theEntry(a));
        // `a`'s move is the newest one, so `c`'s older move must not win.
        expect(theEntry(a).parent!.name.get(), 'target a');
      }),
    );

    test(
      'both copies agree on the location after merging each other',
      () async => await withClock(fakeClock, () async {
        final base = await createFileWithGroups();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        a.move(theEntry(a), groupByName(a, 'target a'));

        proceedSeconds(10);
        theEntry(
          b,
        ).setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('new'));

        final bSaved = await testUtil.saveAndRead(b);
        a.merge(bSaved);
        b.merge(await testUtil.saveAndRead(a));

        logLocation('a after merge', theEntry(a));
        logLocation('b after merge', theEntry(b));
        // `a`'s move is the only move, so both copies have to end up with it.
        expect(theEntry(a).parent!.name.get(), 'target a');
        expect(theEntry(b).parent!.name.get(), 'target a');
      }),
    );

    test(
      'two copies holding the entry in one group agree on when it got there',
      () async => await withClock(fakeClock, () async {
        final base = await createFileWithGroups();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);
        final c = await testUtil.saveAndRead(base);

        // `b` and `a` both move the entry to 'target a', `b` first.
        proceedSeconds(10);
        b.move(theEntry(b), groupByName(b, 'target a'));
        // `c` moves it elsewhere, in between the two.
        proceedSeconds(10);
        c.move(theEntry(c), groupByName(c, 'target b'));
        proceedSeconds(10);
        a.move(theEntry(a), groupByName(a, 'target a'));
        // `b` then edits a field, so `b` wins the data comparison while `a`
        // holds the newer move.
        proceedSeconds(10);
        theEntry(
          b,
        ).setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('new'));

        proceedSeconds(10);
        final aSaved = await testUtil.saveAndRead(a);
        a.merge(await testUtil.saveAndRead(b));
        b.merge(aSaved);
        logLocation('a', theEntry(a));
        logLocation('b', theEntry(b));
        // Both hold the entry in 'target a', so both have to record the same
        // time for it -- the reconciliation has to happen whichever way round
        // the data comparison went.
        expect(
          theEntry(b).times.locationChanged.get(),
          theEntry(a).times.locationChanged.get(),
        );

        // Otherwise `c`'s older move is refused by one copy and accepted by
        // the other, and the entry ends up in different groups per device.
        proceedSeconds(10);
        final cSaved = await testUtil.saveAndRead(c);
        a.merge(cSaved);
        b.merge(await testUtil.saveAndRead(c));
        expect(
          theEntry(b).parent!.name.get(),
          theEntry(a).parent!.name.get(),
        );
        // `a`'s move is the newest of the three, so it wins.
        expect(theEntry(a).parent!.name.get(), 'target a');
      }),
    );

    test(
      'replaying an incoming move records its time, not the merge time',
      () async => await withClock(fakeClock, () async {
        final base = await createFileWithGroups();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);
        final c = await testUtil.saveAndRead(base);

        // `b` moves the entry first, `c` moves it elsewhere afterwards.
        proceedSeconds(10);
        final bMovedAt = clock.now().toUtc();
        b.move(theEntry(b), groupByName(b, 'target a'));
        proceedSeconds(10);
        c.move(theEntry(c), groupByName(c, 'target b'));

        // `a` never moved it, so it replays `b`'s move...
        proceedSeconds(100);
        a.merge(await testUtil.saveAndRead(b));
        logLocation('a after replaying b\'s move', theEntry(a));
        expect(theEntry(a).parent!.name.get(), 'target a');
        // ...and must record when that move happened, not now. Recording the
        // merge time would make this copy look like the most recent mover.
        expect(theEntry(a).times.locationChanged.get(), bMovedAt);

        // So `c`'s later move still wins.
        proceedSeconds(10);
        a.merge(await testUtil.saveAndRead(c));
        expect(theEntry(a).parent!.name.get(), 'target b');
      }),
    );

    test(
      'an imported object keeps the location time it had in the other file',
      () async => await withClock(fakeClock, () async {
        final base = await createFileWithGroups();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        // `b` gains an entry and a group `a` has never seen.
        proceedSeconds(10);
        final createdAt = clock.now().toUtc();
        final newEntry = testUtil.createEntry(
          b,
          groupByName(b, 'target a'),
          'imported',
          'pass',
        );
        final newGroup = b.createGroup(
          parent: groupByName(b, 'target b'),
          name: 'imported group',
        );

        proceedSeconds(10);
        a.merge(await testUtil.saveAndRead(b));

        // Importing is a copy, not a move: the object's location time is the
        // one it carries, not the time it was imported. Stamping the import
        // time would make it beat a genuine later move by a third copy.
        final imported = a.body.rootGroup.getAllEntries().firstWhere(
          (entry) => entry.uuid == newEntry.uuid,
        );
        expect(imported.times.locationChanged.get(), createdAt);
        expect(
          groupByName(a, 'imported group').times.locationChanged.get(),
          newGroup.times.locationChanged.get(),
        );
      }),
    );

    test(
      'two copies holding the group in one place agree on when it got there',
      () async => await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        file.createGroup(parent: file.body.rootGroup, name: 'moving');
        file.createGroup(parent: file.body.rootGroup, name: 'target a');
        file.createGroup(parent: file.body.rootGroup, name: 'target b');
        proceedSeconds(10);
        final base = await testUtil.saveAndRead(file);

        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);
        final c = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        b.move(groupByName(b, 'moving'), groupByName(b, 'target a'));
        proceedSeconds(10);
        c.move(groupByName(c, 'moving'), groupByName(c, 'target b'));
        proceedSeconds(10);
        a.move(groupByName(a, 'moving'), groupByName(a, 'target a'));
        proceedSeconds(10);
        groupByName(b, 'moving').notes.set('edited in b');

        proceedSeconds(10);
        final aSaved = await testUtil.saveAndRead(a);
        a.merge(await testUtil.saveAndRead(b));
        b.merge(aSaved);
        expect(
          groupByName(b, 'moving').times.locationChanged.get(),
          groupByName(a, 'moving').times.locationChanged.get(),
        );

        proceedSeconds(10);
        final cSaved = await testUtil.saveAndRead(c);
        a.merge(cSaved);
        b.merge(await testUtil.saveAndRead(c));
        expect(
          groupByName(b, 'moving').parent!.name.get(),
          groupByName(a, 'moving').parent!.name.get(),
        );
        expect(groupByName(a, 'moving').parent!.name.get(), 'target a');
      }),
    );

    test(
      'the same for a moved group',
      () async => await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        file.createGroup(parent: file.body.rootGroup, name: 'moving');
        file.createGroup(parent: file.body.rootGroup, name: 'target a');
        file.createGroup(parent: file.body.rootGroup, name: 'target b');
        proceedSeconds(10);
        final base = await testUtil.saveAndRead(file);

        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);
        final c = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        c.move(groupByName(c, 'moving'), groupByName(c, 'target b'));

        proceedSeconds(10);
        final aMovedAt = clock.now().toUtc();
        a.move(groupByName(a, 'moving'), groupByName(a, 'target a'));

        proceedSeconds(10);
        groupByName(b, 'moving').notes.set('edited in b');

        a.merge(await testUtil.saveAndRead(b));
        expect(groupByName(a, 'moving').parent!.name.get(), 'target a');
        expect(
          groupByName(a, 'moving').times.locationChanged.get(),
          aMovedAt,
        );

        a.merge(await testUtil.saveAndRead(c));
        expect(groupByName(a, 'moving').parent!.name.get(), 'target a');
      }),
    );
  });
}
