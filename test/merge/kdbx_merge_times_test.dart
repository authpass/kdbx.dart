import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';

import '../internal/test_utils.dart';

final _logger = Logger('kdbx_merge_times_test');

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

  /// A saved file with one entry, password 'base', and one empty sub group.
  Future<KdbxFile> createBase() async {
    final file = testUtil.createEmptyFile();
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

  void setPassword(KdbxFile file, String value) => theEntry(
    file,
  ).setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value));

  List<String?> historyPasswords(KdbxEntry entry) =>
      entry.history.map(password).toList();

  DateTime? lastModified(KdbxObject object) =>
      object.times.lastModificationTime.get();

  void logEntry(String label, KdbxEntry entry) {
    _logger.info(
      '$label: password=${password(entry)} '
      'lastModified=${lastModified(entry)} '
      'history=${historyPasswords(entry)}',
    );
  }

  group('a merge adopts the times of what it takes in', () {
    test(
      'an incoming edit keeps the time it was made at, not the merge time',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        final editedAt = clock.now().toUtc();
        setPassword(b, 'from b');

        // The merge happens well after the edit, so the two times differ.
        proceedSeconds(100);
        a.merge(await testUtil.saveAndRead(b));
        logEntry('a after merge', theEntry(a));

        expect(password(theEntry(a)), 'from b');
        expect(lastModified(theEntry(a)), editedAt);
        // the access time travels with the change too; stamping it would not
        // decide a merge, but it would still be a fabricated time.
        expect(theEntry(a).times.lastAccessTime.get(), editedAt);
        expect(historyPasswords(theEntry(a)), ['base']);

        // And it is the time that gets written.
        proceedSeconds(10);
        final reread = await testUtil.saveAndRead(a);
        expect(lastModified(theEntry(reread)), editedAt);
      }),
    );

    test(
      'merging back the other way changes nothing',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(b, 'from b');
        final bSaved = await testUtil.saveAndRead(b);

        proceedSeconds(100);
        a.merge(bSaved);
        proceedSeconds(10);
        final aSaved = await testUtil.saveAndRead(a);

        proceedSeconds(10);
        final bEntry = theEntry(bSaved);
        final bTimeBefore = lastModified(bEntry);
        final bHistoryBefore = historyPasswords(bEntry);
        final merge = bSaved.merge(aSaved);
        logEntry('b after merging a', bEntry);

        // `a` took `b`'s edit, so the two copies hold the same state - and the
        // same time for it, or `b` would now find `a` newer and take it back.
        expect(lastModified(theEntry(aSaved)), bTimeBefore);
        expect(password(bEntry), 'from b');
        expect(lastModified(bEntry), bTimeBefore);
        expect(historyPasswords(bEntry), bHistoryBefore);
        expect(merge.changes, isEmpty);
      }),
    );

    test(
      'merging the same file twice changes nothing the second time',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(b, 'from b');
        final bSaved = await testUtil.saveAndRead(b);

        proceedSeconds(100);
        a.merge(bSaved);
        final timeAfterFirst = lastModified(theEntry(a));
        final historyAfterFirst = historyPasswords(theEntry(a));

        proceedSeconds(100);
        final second = a.merge(bSaved);

        expect(second.changes, isEmpty);
        expect(lastModified(theEntry(a)), timeAfterFirst);
        expect(historyPasswords(theEntry(a)), historyAfterFirst);
      }),
    );

    test(
      'a replica that relays an older edit does not make it win',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final remote = await testUtil.saveAndRead(base);
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(remote, 'p1');
        final remoteSaved = await testUtil.saveAndRead(remote);

        // `a` edits later than `remote` did.
        proceedSeconds(10);
        setPassword(a, 'p2');
        final aSaved = await testUtil.saveAndRead(a);

        // `b` relays `remote`'s older edit, after both edits happened.
        proceedSeconds(10);
        b.merge(remoteSaved);
        final bSaved = await testUtil.saveAndRead(b);

        proceedSeconds(10);
        bSaved.merge(aSaved);
        logEntry('b after merging a', theEntry(bSaved));
        expect(password(theEntry(bSaved)), 'p2');

        proceedSeconds(10);
        final aAfter = await testUtil.saveAndRead(aSaved);
        aAfter.merge(await testUtil.saveAndRead(bSaved));
        logEntry('a after merging b', theEntry(aAfter));
        expect(password(theEntry(aAfter)), 'p2');
      }),
    );

    test(
      'repeated merge and save rounds do not add revisions',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);
        var b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(a, 'edited once');
        a = await testUtil.saveAndRead(a);

        final aHistory = historyPasswords(theEntry(a));
        for (var round = 0; round < 5; round++) {
          proceedSeconds(10);
          b.merge(a);
          b = await testUtil.saveAndRead(b);
          proceedSeconds(10);
          a.merge(b);
          a = await testUtil.saveAndRead(a);
          logEntry('a after round $round', theEntry(a));
        }

        expect(password(theEntry(a)), 'edited once');
        expect(password(theEntry(b)), 'edited once');
        expect(historyPasswords(theEntry(a)), aHistory);
        expect(historyPasswords(theEntry(b)), aHistory);
      }),
    );

    test(
      'an incoming group change keeps the time it was made at',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        final editedAt = clock.now().toUtc();
        theGroup(b).name.set('renamed in b');

        proceedSeconds(100);
        a.merge(await testUtil.saveAndRead(b));
        expect(theGroup(a).name.get(), 'renamed in b');
        expect(lastModified(theGroup(a)), editedAt);

        proceedSeconds(10);
        final reread = await testUtil.saveAndRead(a);
        expect(lastModified(theGroup(reread)), editedAt);
      }),
    );
  });

  group('a merge keeps the local state it overwrites', () {
    test(
      'an unsaved local edit is kept as a revision when a newer edit wins',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(a, 'unsaved in a');
        expect(theEntry(a).isDirty, isTrue);

        proceedSeconds(10);
        setPassword(b, 'newer in b');
        a.merge(await testUtil.saveAndRead(b));
        logEntry('a after merge', theEntry(a));

        expect(password(theEntry(a)), 'newer in b');
        expect(historyPasswords(theEntry(a)), ['base', 'unsaved in a']);
      }),
    );

    test(
      'a saved local state is kept as a revision when a newer edit wins',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        var a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(a, 'saved in a');
        a = await testUtil.saveAndRead(a);

        proceedSeconds(10);
        setPassword(b, 'newer in b');
        a.merge(await testUtil.saveAndRead(b));

        expect(password(theEntry(a)), 'newer in b');
        expect(historyPasswords(theEntry(a)), ['base', 'saved in a']);
      }),
    );

    test(
      'a local edit after the merge keeps the merged state as a revision',
      () async => await withClock(fakeClock, () async {
        final base = await createBase();
        final a = await testUtil.saveAndRead(base);
        final b = await testUtil.saveAndRead(base);

        proceedSeconds(10);
        setPassword(b, 'from b');
        proceedSeconds(10);
        a.merge(await testUtil.saveAndRead(b));

        // edited before `a` was saved: the state the merge brought in came
        // from another device, so it is a revision of its own, the same as
        // the state a merge overwrites.
        proceedSeconds(10);
        final editedAt = clock.now().toUtc();
        setPassword(a, 'after merge');

        expect(password(theEntry(a)), 'after merge');
        expect(lastModified(theEntry(a)), editedAt);
        expect(historyPasswords(theEntry(a)), ['base', 'from b']);
      }),
    );
  });
}
