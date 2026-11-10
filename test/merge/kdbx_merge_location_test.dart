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
