import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

/// Entry history is bounded by the limits the database itself declares, and
/// the pruning happens when a revision is taken — never on save.
///
/// The clock is faked throughout, because "oldest" is decided by
/// `lastModificationTime` and these tests assert *which* revision survived.
/// Revisions sharing an instant are not ordered arbitrarily — the tie goes to
/// the lowest index — and one test below pins that rather than avoiding it.
///
/// It starts at a plain date rather than at zero on purpose. The epoch is
/// exactly what `_modifiedAtOrMinDate` substitutes for a missing timestamp,
/// so a clock starting there makes every genuinely-timed revision tie with
/// the sentinel, and tests about missing timestamps pass through the
/// tie-break instead of through the behaviour they claim to check.
void main() {
  final testUtil = TestUtil();

  final startOfTime = DateTime.utc(2020, 1, 1);
  var now = startOfTime;
  final fakeClock = Clock(() => now);

  setUp(() {
    now = startOfTime;
  });

  /// Adds exactly one revision.
  ///
  /// The save is the part that matters: `onBeforeModify` fires on the
  /// transition from clean to dirty, so without it a second edit would amend
  /// the pending change instead of snapshotting again.
  Future<void> editAndSave(KdbxFile file, KdbxEntry entry, String title) async {
    now = now.add(const Duration(seconds: 1));
    entry.setString(TestUtil.keyTitle, PlainValue(title));
    await file.save();
  }

  List<String?> titlesOf(KdbxEntry entry) => entry.history
      .map((revision) => revision.getString(TestUtil.keyTitle)?.getText())
      .toList();

  Future<(KdbxFile, KdbxEntry)> fileWithCleanEntry() async {
    final file = testUtil.createEmptyFile();
    final entry = testUtil.createEntry(
      file,
      file.body.rootGroup,
      'user',
      'pass',
    );
    await file.save();
    return (file, entry);
  }

  group('history maintenance', () {
    test('keeps the newest revisions up to historyMaxItems', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(3);

        for (var i = 1; i <= 6; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        // The revision taken before 'title 6' holds 'title 5', so the three
        // newest are 3, 4 and 5 — and they are the three that survived.
        expect(entry.history, hasLength(3));
        expect(titlesOf(entry), ['title 3', 'title 4', 'title 5']);
        expect(entry.getString(TestUtil.keyTitle)!.getText(), 'title 6');
      });
    });

    test('keeps nothing when historyMaxItems is zero', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(0);

        for (var i = 1; i <= 3; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        expect(entry.history, isEmpty);
      });
    });

    test('treats a negative limit as unlimited', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(-1);
        file.body.meta.historyMaxSize.set(-1);

        for (var i = 1; i <= 6; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        expect(entry.history, hasLength(6));
      });
    });

    test('treats an absent limit as unlimited, not as the default', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.remove();
        file.body.meta.historyMaxSize.remove();
        expect(file.body.meta.historyMaxItems.get(), isNull);
        expect(file.body.meta.historyMaxSize.get(), isNull);

        for (var i = 1; i <= 21; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        // Past this package's own default of 20 deliberately: a database that
        // declares no limit does not get one imposed on it, because deleting
        // revisions nobody asked us to bound is not ours to do.
        expect(entry.history, hasLength(21));
      });
    });

    test('breaks a tie between revisions by taking the lowest index', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(2);

        // The clock is deliberately not advanced here, so every revision
        // records the same instant — which is what two edits inside one tick
        // produce in a real app, and what a merge produces routinely.
        for (var i = 1; i <= 4; i++) {
          entry.setString(TestUtil.keyTitle, PlainValue('title $i'));
          await file.save();
        }

        expect(titlesOf(entry), ['title 2', 'title 3']);
      });
    });

    test('treats a revision with no modification time as the oldest', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(-1);

        for (var i = 1; i <= 3; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        // Strip the timestamp off the *newest* revision. Nothing reachable
        // through this package produces that — `KdbxTimes.read` backfills the
        // field — but the obvious null handling made a missing timestamp mean
        // "delete this one last", when it has to mean the opposite.
        entry.history.last.times.lastModificationTime.remove();
        expect(entry.history.last.times.lastModificationTime.get(), isNull);

        file.body.meta.historyMaxItems.set(2);
        await editAndSave(file, entry, 'title 4');

        // The untimed revision went first, then the genuinely oldest one.
        expect(titlesOf(entry), ['title 1', 'title 3']);
      });
    });

    test('the pruned revisions are gone from the saved file', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(2);

        for (var i = 1; i <= 5; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        final reread = await testUtil.saveAndRead(file);
        final rereadEntry = reread.body.rootGroup.entries.single;

        expect(rereadEntry.history, hasLength(2));
        expect(titlesOf(rereadEntry), ['title 3', 'title 4']);
      });
    });

    test(
      'leaves an over-limit entry alone until that entry is edited',
      () async {
        await withClock(fakeClock, () async {
          final file = testUtil.createEmptyFile();
          file.body.meta.historyMaxItems.set(-1);
          final untouched = testUtil.createEntry(
            file,
            file.body.rootGroup,
            'untouched',
            'pass',
          );
          final edited = testUtil.createEntry(
            file,
            file.body.rootGroup,
            'edited',
            'pass',
          );
          await file.save();

          for (var i = 1; i <= 5; i++) {
            await editAndSave(file, untouched, 'untouched $i');
          }
          expect(untouched.history, hasLength(5));

          // Now the database declares a limit that `untouched` already violates.
          file.body.meta.historyMaxItems.set(2);
          await file.save();

          // Saving did not prune it. This is the property that makes the change
          // safe to ship: opening a database that has grown past its limits and
          // saving it does not rewrite every entry in it.
          expect(untouched.history, hasLength(5));

          await editAndSave(file, edited, 'edited 1');

          // Editing a different entry did not prune it either.
          expect(untouched.history, hasLength(5));
          expect(edited.history, hasLength(1));

          // It survives a round-trip as well — and then the first edit to
          // that entry is what enforces the limit. Without that last pair of
          // assertions this test would pass just as well against a build that
          // does no pruning at all.
          final reread = await testUtil.saveAndRead(file);
          final rereadUntouched = reread.body.rootGroup.entries.firstWhere(
            (candidate) =>
                candidate.getString(KdbxKeyCommon.USER_NAME)?.getText() ==
                'untouched',
          );
          expect(rereadUntouched.history, hasLength(5));

          await editAndSave(reread, rereadUntouched, 'untouched 6');
          expect(rereadUntouched.history, hasLength(2));
        });
      },
    );

    test(
      'moving an entry to the recycle bin leaves its history alone',
      () async {
        await withClock(fakeClock, () async {
          final (file, entry) = await fileWithCleanEntry();
          file.body.meta.historyMaxItems.set(-1);

          for (var i = 1; i <= 4; i++) {
            await editAndSave(file, entry, 'title $i');
          }
          expect(entry.history, hasLength(4));

          file.body.meta.historyMaxItems.set(2);
          now = now.add(const Duration(seconds: 1));
          file.deleteEntry(entry);

          // A move is a structural change, so it records no revision, so
          // there is nothing to maintain — and the history of a trashed entry
          // stays intact, which is exactly the history someone would want if
          // they restore it from the bin.
          //
          // This used to prune to 2, because a move went through a plain
          // `modify` and so took a revision on the way to the trash. That was
          // documented here as surprising and "the next thing to look at";
          // `modifyStructural` fixed it.
          expect(entry.history, hasLength(4));

          // The limit still applies to a real edit afterwards — and that edit
          // picks up the revision the move deferred, so this also covers
          // `_revisionPending` meeting the pruning.
          await editAndSave(file, entry, 'title 5');
          expect(entry.history, hasLength(2));
        });
      },
    );

    /// Two copies that diverge from a common base, each with a revision the
    /// other has never seen.
    ///
    /// Which side the merge takes is decided by whose *current* state is
    /// newer, so the order of the edits below is what selects the branch of
    /// [KdbxEntry.merge] under test. Here B is edited last and wins, which is
    /// the branch that goes through `modify` and therefore takes a revision of
    /// its own.
    ///
    /// The resulting arrangement is the one that can tell pruning before the
    /// union apart from pruning after it. A revision B alone holds is *newer*
    /// than one A alone holds, so the two orders do not merely keep different
    /// revisions, they keep different numbers of them: pruning inside `modify`
    /// trims A to the limit and the import then pushes it back over, while
    /// pruning at the end applies the limit to everything at once.
    Future<(KdbxFile, KdbxEntry, KdbxFile)> incomingWinsWithOwnHistory() async {
      final base = testUtil.createEmptyFile();
      testUtil.createEntry(base, base.body.rootGroup, 'user', 'pass');
      base.body.meta.historyMaxItems.set(-1);

      final fileA = await testUtil.saveAndRead(base);
      final entryA = fileA.body.rootGroup.entries.single;
      final fileB = await testUtil.saveAndRead(base);
      final entryB = fileB.body.rootGroup.entries.single;

      // A first: its revisions are the older ones.
      await editAndSave(fileA, entryA, 'a 1');
      await editAndSave(fileA, entryA, 'a 2');
      // Then B, so B's current state is the newest and the merge takes it.
      await editAndSave(fileB, entryB, 'b 1');
      await editAndSave(fileB, entryB, 'b 2');

      return (fileA, entryA, fileB);
    }

    test(
      'a merge prunes the union, keeping the newest of both sides',
      () async {
        await withClock(fakeClock, () async {
          final (fileA, entryA, fileB) = await incomingWinsWithOwnHistory();

          fileA.body.meta.historyMaxItems.set(2);
          fileA.merge(fileB);

          // Four revisions went in — A's base, 'a 1', the 'a 2' snapshot the
          // merge itself took, and 'b 1' imported from B — and the two newest
          // came out. 'b 1' is newer than 'a 2' despite arriving from the other
          // copy, and that is the point: which revisions survive depends on
          // when they were made, not on which file they were found in.
          expect(entryA.history, hasLength(2));
          expect(titlesOf(entryA), ['a 2', 'b 1']);
        });
      },
    );

    test('a merge leaves an entry neither side touched alone', () async {
      await withClock(fakeClock, () async {
        final (base, baseEntry) = await fileWithCleanEntry();
        base.body.meta.historyMaxItems.set(-1);
        for (var i = 1; i <= 5; i++) {
          await editAndSave(base, baseEntry, 'title $i');
        }

        // Two copies of one file with nothing to merge between them.
        final fileA = await testUtil.saveAndRead(base);
        final entryA = fileA.body.rootGroup.entries.single;
        final fileB = await testUtil.saveAndRead(base);

        fileA.body.meta.historyMaxItems.set(2);
        fileA.merge(fileB);

        // `KdbxGroup._mergeSubObjects` calls `KdbxEntry.merge` for every entry
        // the other copy also has, which in a real sync is all of them. So an
        // unconditional prune here would drop three revisions of a password
        // that neither side edited, reported to the user as a merge with zero
        // changes — the mass rewrite that pruning in `onBeforeModify` exists
        // to avoid, arriving by a different road.
        expect(entryA.history, hasLength(5));
        expect(entryA.isDirty, isFalse);

        // The user editing it does apply the limit.
        await editAndSave(fileA, entryA, 'title 6');
        expect(entryA.history, hasLength(2));
      });
    });

    /// This used to pin the opposite: that a merge into a dirty entry took no
    /// revision, so had nothing to prune. That was the overwrite which lost
    /// the unsaved edit (issue #23). The merge now always keeps the state it
    /// overwrites, so this entry's history does grow, and the limit applies to
    /// it like to any other growth. That a merge which grows nothing prunes
    /// nothing is still pinned, by the two tests either side of this one.
    test(
      'a merge over unsaved edits keeps them as the newest revision',
      () async {
        await withClock(fakeClock, () async {
          final (base, _) = await fileWithCleanEntry();
          base.body.meta.historyMaxItems.set(-1);

          final fileA = await testUtil.saveAndRead(base);
          final entryA = fileA.body.rootGroup.entries.single;
          final fileB = await testUtil.saveAndRead(base);
          final entryB = fileB.body.rootGroup.entries.single;

          for (var i = 1; i <= 3; i++) {
            await editAndSave(fileA, entryA, 'a $i');
          }
          // A fourth edit that is *not* saved, so the entry stays dirty.
          now = now.add(const Duration(seconds: 1));
          entryA.setString(TestUtil.keyTitle, PlainValue('a 4 unsaved'));
          expect(entryA.isDirty, isTrue);
          expect(entryA.history, hasLength(4));

          // Later than A, and holding no revision A lacks, so the merge takes
          // B's fields and the import loop brings in nothing.
          await editAndSave(fileB, entryB, 'b 1');

          fileA.body.meta.historyMaxItems.set(2);
          fileA.merge(fileB);

          // The entry was already dirty, so `onBeforeModify` - which only runs
          // on the clean-to-dirty transition - would never have kept
          // 'a 4 unsaved'. The merge keeps it itself. This is the path
          // AuthPass actually merges on, because it merges after a save
          // conflict, with the user's unsaved edits still pending.
          //
          // Five revisions against a limit of two: the newest two survive,
          // and the user's unsaved edit is the newest of all.
          expect(titlesOf(entryA), ['a 3', 'a 4 unsaved']);
          // The merge did apply, so this is not a no-op being measured.
          expect(entryA.getString(TestUtil.keyTitle)?.getText(), 'b 1');
        });
      },
    );

    test(
      'a merge keeps unsaved edits even when newer revisions arrive with them',
      () async {
        await withClock(fakeClock, () async {
          final (base, _) = await fileWithCleanEntry();
          base.body.meta.historyMaxItems.set(-1);

          final fileA = await testUtil.saveAndRead(base);
          final entryA = fileA.body.rootGroup.entries.single;
          final fileB = await testUtil.saveAndRead(base);
          final entryB = fileB.body.rootGroup.entries.single;

          // A edits and does not save - a long-open session, say.
          now = now.add(const Duration(seconds: 1));
          entryA.setString(TestUtil.keyTitle, PlainValue('a unsaved'));

          // Meanwhile B saves three edits, all newer than A's.
          for (var i = 1; i <= 3; i++) {
            await editAndSave(fileB, entryB, 'b $i');
          }

          fileA.body.meta.historyMaxItems.set(2);
          fileA.merge(fileB);

          // B's 'b 1' and 'b 2' come in with the merge and are newer than
          // 'a unsaved', so pruning by date alone would evict A's edit and
          // leave it nowhere: B never saw it. It is the one revision the limit
          // has to spare; everything else is still held to it.
          expect(entryA.getString(TestUtil.keyTitle)?.getText(), 'b 3');
          expect(titlesOf(entryA), ['a unsaved', 'b 2']);
        });
      },
    );

    /// Pinned while the fix for it was in review on another branch, and now
    /// active: `KdbxGroup._mergeSubObjects` used to call `file.move` before
    /// `KdbxEntry.merge`, through an unsuppressed `modify`, so a move took a
    /// revision and pruned mid-merge with [_isMerging] false — the one
    /// ordering this file exists to remove, reached by a path `merge` could
    /// not gate. `modifyStructural` closed it: a move records no revision, so
    /// nothing here grows and nothing is pruned.
    test(
      'a merge does not prune an entry the other copy only moved',
      () async {
        await withClock(fakeClock, () async {
          final (base, baseEntry) = await fileWithCleanEntry();
          base.body.meta.historyMaxItems.set(-1);
          for (var i = 1; i <= 5; i++) {
            await editAndSave(base, baseEntry, 'title $i');
          }

          final fileA = await testUtil.saveAndRead(base);
          final entryA = fileA.body.rootGroup.entries.single;
          final fileB = await testUtil.saveAndRead(base);
          final entryB = fileB.body.rootGroup.entries.single;

          // B only moves it. Nobody edits anything.
          now = now.add(const Duration(seconds: 1));
          final subGroup = fileB.createGroup(
            parent: fileB.body.rootGroup,
            name: 'Sub Group',
          );
          fileB.move(entryB, subGroup);
          await fileB.save();

          fileA.body.meta.historyMaxItems.set(2);
          fileA.merge(fileB);

          expect(entryA.history, hasLength(5));
          // The move did reach this copy, so this is not a no-op being
          // measured.
          expect(entryA.parent?.name.get(), 'Sub Group');
        });
      },
    );

    test('a merge keeps every revision when the union fits', () async {
      await withClock(fakeClock, () async {
        final (fileA, entryA, fileB) = await incomingWinsWithOwnHistory();

        fileA.body.meta.historyMaxItems.set(10);
        fileA.merge(fileB);

        // A guard against over-pruning, and nothing more: it passes just as
        // well against a merge that never prunes at all, so it cannot show
        // the prune works. What it rules out is the limit biting when nothing
        // exceeds it.
        //
        // Note what it does *not* claim. Pruning the union does cost
        // revisions only one copy had once the limit bites — the sibling test
        // above drops 'a 1', which B never held. That is the limit doing its
        // job by date, not a property worth defending.
        expect(entryA.history, hasLength(4));
        expect(titlesOf(entryA), containsAll(['a 1', 'a 2', 'b 1']));
      });
    });

    test(
      'a merge prunes when we are the newer copy, without restamping',
      () async {
        await withClock(fakeClock, () async {
          final base = testUtil.createEmptyFile();
          testUtil.createEntry(base, base.body.rootGroup, 'user', 'pass');
          base.body.meta.historyMaxItems.set(-1);

          final fileA = await testUtil.saveAndRead(base);
          final entryA = fileA.body.rootGroup.entries.single;
          final fileB = await testUtil.saveAndRead(base);
          final entryB = fileB.body.rootGroup.entries.single;

          // B first this time, so A's current state is the newest and the merge
          // goes down the outgoing-changes branch — which never calls `modify`.
          // That is the branch where pruning has to mark the entry dirty by
          // itself or the removal would never reach the file.
          await editAndSave(fileB, entryB, 'b 1');
          await editAndSave(fileB, entryB, 'b 2');
          await editAndSave(fileA, entryA, 'a 1');
          await editAndSave(fileA, entryA, 'a 2');

          expect(entryA.isDirty, isFalse);
          final modifiedBeforeMerge = entryA.times.lastModificationTime.get();

          fileA.body.meta.historyMaxItems.set(2);
          fileA.merge(fileB);

          expect(entryA.history, hasLength(2));
          expect(titlesOf(entryA), ['a 1', 'b 2']);

          // Pruning is a change that has to be saved. Asserted on the entry
          // rather than on the file: a merge clones revisions, and creating a
          // clone puts it in `file.dirtyObjects` too, so `fileA.isDirty`
          // would be true here even with the pruning removed entirely.
          expect(entryA.isDirty, isTrue);
          // ...but not a modification of the entry. A bumped timestamp here
          // would make this copy win the next merge against a B that never
          // changed again, quietly reversing which side is authoritative.
          expect(entryA.times.lastModificationTime.get(), modifiedBeforeMerge);
        });
      },
    );

    test(
      'a merge does not evict our revisions for copies of theirs',
      () async {
        await withClock(fakeClock, () async {
          Future<void> editAt(
            KdbxFile file,
            KdbxEntry entry,
            int second,
            String title,
          ) async {
            now = startOfTime.add(Duration(seconds: second));
            entry.setString(TestUtil.keyTitle, PlainValue(title));
            await file.save();
          }

          final base = testUtil.createEmptyFile();
          testUtil.createEntry(base, base.body.rootGroup, 'user', 'pass');
          base.body.meta.historyMaxItems.set(-1);

          final fileA = await testUtil.saveAndRead(base);
          final entryA = fileA.body.rootGroup.entries.single;
          final fileB = await testUtil.saveAndRead(base);
          final entryB = fileB.body.rootGroup.entries.single;

          // The shape that matters: B's only edit lands *inside* A's
          // timeline, not before all of it. A replica that is simply behind
          // everything hides this, because then the revision the merge keeps
          // of B's state is the oldest and the prune takes it straight back.
          await editAt(fileB, entryB, 25, 'b 1');
          for (final second in [10, 20, 30, 40]) {
            await editAt(fileA, entryA, second, 'a ${second ~/ 10}');
          }
          expect(titlesOf(entryA), [null, 'a 1', 'a 2', 'a 3']);

          fileA.body.meta.historyMaxItems.set(3);
          // B never changes again, so every round takes the outgoing branch.
          for (var round = 1; round <= 3; round++) {
            fileA.merge(fileB);
          }

          // Round one keeps B's state and the limit then drops the two
          // oldest, which is the limit doing its job on a union that really
          // grew. Rounds two and three recognise that state and change
          // nothing.
          //
          // Before the lookup used B's timestamp this ground down to
          // ['a 3', 'b 1', 'b 1'] — three of A's own revisions destroyed and
          // one of B's duplicated — a little more lost on every sync with a
          // replica that was never written to again.
          expect(titlesOf(entryA), ['a 2', 'a 3', 'b 1']);
        });
      },
    );

    test(
      'a merge of an entry the other copy moved and edited keeps our revision',
      () async {
        await withClock(fakeClock, () async {
          final base = testUtil.createEmptyFile();
          testUtil.createEntry(base, base.body.rootGroup, 'user', 'pass');

          final fileA = await testUtil.saveAndRead(base);
          final entryA = fileA.body.rootGroup.entries.single;
          final fileB = await testUtil.saveAndRead(base);
          final entryB = fileB.body.rootGroup.entries.single;

          await editAndSave(fileA, entryA, 'a 1');
          expect(entryA.isDirty, isFalse);

          // B moves it *and* edits it, after A.
          now = now.add(const Duration(seconds: 1));
          final subGroup = fileB.createGroup(
            parent: fileB.body.rootGroup,
            name: 'Sub Group',
          );
          fileB.move(entryB, subGroup);
          await editAndSave(fileB, entryB, 'b 1');

          fileA.merge(fileB);

          // `mergeLocationChangedFrom` runs before the branch and goes
          // through `modifyStructural`, which dirties the entry without
          // recording a revision. So by the time the incoming-changes branch
          // runs, the entry is already dirty and `onBeforeModify` would never
          // fire: the revision holding our own pre-merge state has to come
          // from the branch recording it explicitly. Drop that and 'a 1'
          // disappears silently while the merge still applies, which is why
          // this is pinned here. It must also be recorded only once, though
          // the move left a `_revisionPending` catch-up waiting.
          expect(titlesOf(entryA), [null, 'a 1']);
          expect(entryA.getString(TestUtil.keyTitle)?.getText(), 'b 1');
          expect(entryA.parent?.name.get(), 'Sub Group');
        });
      },
    );

    test('a revision dated in the future outlives every real one', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(-1);

        for (var i = 1; i <= 4; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        // A revision stamped by a device whose clock is wrong. Setting the
        // field is not enough on its own — `onAfterAnyModify` re-stamps it
        // from the clock — so the clock has to be the wrong one.
        final realNow = now;
        now = DateTime.utc(2099);
        entry.history[1].times.lastModificationTime.setToNow();
        now = realNow;
        expect(
          entry.history[1].times.lastModificationTime.get(),
          DateTime.utc(2099),
        );

        file.body.meta.historyMaxItems.set(1);
        await editAndSave(file, entry, 'title 5');

        // Every genuine revision was deleted to keep the bogus one, and it
        // will keep winning for as long as the entry is edited. KeePass's
        // `RemoveOldestBackup` does exactly this, so it is pinned rather than
        // fixed — but anyone who decides to clamp instead now has to change a
        // test, which is the point.
        expect(entry.history, hasLength(1));
        expect(
          entry.history.single.times.lastModificationTime.get(),
          DateTime.utc(2099),
        );
      });
    });

    test(
      'an entry whose clock went backwards loses its own snapshot',
      () async {
        await withClock(fakeClock, () async {
          final (file, entry) = await fileWithCleanEntry();
          file.body.meta.historyMaxItems.set(3);

          for (var i = 1; i <= 3; i++) {
            await editAndSave(file, entry, 'title $i');
          }
          expect(entry.history, hasLength(3));

          // The clock goes backwards, which is a second device with the wrong
          // time. The entry is stamped in the past, so the *next* snapshot
          // carries a time older than every revision above it.
          now = DateTime.utc(2010);
          entry.setString(TestUtil.keyTitle, PlainValue('rewound'));
          await file.save();
          final before = titlesOf(entry);

          now = now.add(const Duration(seconds: 1));
          entry.setString(TestUtil.keyTitle, PlainValue('after the rewind'));
          await file.save();

          // The snapshot holding 'rewound' was the oldest the instant it was
          // taken, so the edit that created it is the edit that threw it away:
          // the value just overwritten cannot be recovered. KeePass has the
          // same property.
          expect(titlesOf(entry), before);
          expect(titlesOf(entry), isNot(contains('rewound')));
        });
      },
    );

    group('historyMaxSize', () {
      test('does not charge for an attachment the entry still holds', () async {
        await withClock(fakeClock, () async {
          final (file, entry) = await fileWithCleanEntry();
          file.body.meta.historyMaxItems.set(-1);

          entry.createBinary(
            isProtected: false,
            name: 'big.bin',
            bytes: Uint8List(64 * 1024),
          );
          await file.save();

          // A limit far below the attachment, which is still attached. Take
          // the seed out of `_historySize` and every revision is over this
          // limit on its own, so the history empties completely — while every
          // other test in this file keeps passing. This is the only guard on
          // that one line, and it is the line the whole size metric turns on.
          file.body.meta.historyMaxSize.set(1024);

          for (var i = 1; i <= 5; i++) {
            await editAndSave(file, entry, 'title $i');
          }

          expect(entry.history, hasLength(6));
        });
      });

      test('counts an attachment every revision shares only once', () async {
        await withClock(fakeClock, () async {
          final (file, entry) = await fileWithCleanEntry();
          file.body.meta.historyMaxItems.set(-1);
          file.body.meta.historyMaxSize.set(3 * 1024 * 1024);

          entry.createBinary(
            isProtected: false,
            name: 'attachment.bin',
            bytes: Uint8List(1024 * 1024),
          );
          await file.save();

          for (var i = 1; i <= 8; i++) {
            await editAndSave(file, entry, 'title $i');
          }

          // Billed per revision, as KeePass bills it, the third edit would
          // start deleting revisions — to reclaim nothing, because the file
          // holds one copy of these bytes however many revisions point at
          // them. Nine revisions of a 1 MiB attachment fit in 3 MiB here.
          expect(entry.history, hasLength(9));
        });
      });

      test('prunes once an attachment is held only by history', () async {
        await withClock(fakeClock, () async {
          final (file, entry) = await fileWithCleanEntry();
          final key = KdbxKey('attachment.bin');
          file.body.meta.historyMaxItems.set(-1);

          entry.createBinary(
            isProtected: false,
            name: 'attachment.bin',
            bytes: Uint8List(1024),
          );
          await file.save();

          for (var i = 1; i <= 3; i++) {
            await editAndSave(file, entry, 'title $i');
          }

          // Detaching it from the live entry is what makes it cost something:
          // the bytes are now reachable only through the revisions that still
          // reference them.
          now = now.add(const Duration(seconds: 1));
          entry.removeBinary(key);
          await file.save();
          expect(entry.getBinary(key), isNull);

          file.body.meta.historyMaxSize.set(900);
          await editAndSave(file, entry, 'title 4');

          // Every revision carrying the attachment had to go, and the one
          // left does not carry it. Asserted on the attachment rather than on
          // the title, because two of those revisions held 'title 3' and the
          // interesting thing about the survivor is not its title.
          expect(entry.history, hasLength(1));
          expect(entry.history.single.getBinary(key), isNull);
        });
      });

      test('empties the history when no single revision fits', () async {
        await withClock(fakeClock, () async {
          final (file, entry) = await fileWithCleanEntry();
          file.body.meta.historyMaxItems.set(-1);
          file.body.meta.historyMaxSize.set(1);

          for (var i = 1; i <= 3; i++) {
            await editAndSave(file, entry, 'title $i');
          }

          // There is no floor of one revision kept, in KeePass either. This
          // is the most destructive branch in the feature, so it is pinned.
          expect(entry.history, isEmpty);
        });
      });
    });

    /// What a duplicate-uuid repair folds in is the last copy of itself: the
    /// repair records no deleted object and does not travel, so nothing else
    /// holds that content. It is also stamped older than the survivor's own
    /// revisions, which makes it the first thing the limits would reach for.
    group('duplicate-uuid repair', () {
      List<String?> usernamesOf(KdbxEntry entry) => entry.history
          .map(
            (revision) =>
                revision.getString(KdbxKeyCommon.USER_NAME)?.getText(),
          )
          .toList();

      /// A file whose root group holds two live entries sharing one uuid.
      /// `survivor` is the newer and has history of its own; the other holds
      /// [absorbedUser] and nothing else.
      ///
      /// One edit of the survivor always happens after the uuid is forced,
      /// because forcing it restamps the doomed copy — leave it out and that
      /// copy is the newest, so the repair elects it and folds the survivor
      /// in instead. [extraSurvivorEdits] are on top of that one.
      Future<(KdbxFile, KdbxEntry)> fileWithDuplicate({
        required String absorbedUser,
        required int extraSurvivorEdits,
      }) async {
        final file = testUtil.createEmptyFile();
        final doomed = testUtil.createEntry(
          file,
          file.body.rootGroup,
          absorbedUser,
          'pass',
        );
        now = now.add(const Duration(seconds: 1));
        final survivor = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'survivor',
          'pass',
        );
        // Forcing the uuid restamps, so it has to happen before the
        // survivor's edits or the doomed copy would be elected instead.
        now = now.add(const Duration(seconds: 1));
        doomed.forceSetUuid(survivor.uuid);
        await file.save();
        for (var i = 0; i <= extraSurvivorEdits; i++) {
          await editAndSave(file, survivor, 'survivor $i');
        }
        return (file, survivor);
      }

      test('repaired content outlives the next unrelated edit', () async {
        await withClock(fakeClock, () async {
          final (file, survivor) = await fileWithDuplicate(
            absorbedUser: 'only-copy-of-this',
            extraSurvivorEdits: 3,
          );

          file.body.meta.historyMaxItems.set(3);
          expect(file.mergeDuplicateUuidEntries(), hasLength(1));
          expect(usernamesOf(survivor), contains('only-copy-of-this'));

          // The edit takes a revision, which prunes — and the absorbed one is
          // the oldest, so it is exactly what the limit would take first.
          await editAndSave(file, survivor, 'later');

          expect(survivor.history, hasLength(3));
          expect(usernamesOf(survivor), contains('only-copy-of-this'));
        });
      });

      test('a history of nothing but repaired content is left whole', () async {
        await withClock(fakeClock, () async {
          final (file, survivor) = await fileWithDuplicate(
            absorbedUser: 'only-copy-of-this',
            extraSurvivorEdits: 0,
          );

          // Zero keeps nothing, which is the one limit that would otherwise
          // empty the history outright.
          file.body.meta.historyMaxItems.set(0);
          expect(file.mergeDuplicateUuidEntries(), hasLength(1));
          expect(usernamesOf(survivor), contains('only-copy-of-this'));
          await editAndSave(file, survivor, 'later');

          // Everything prunable went; what the repair rescued stayed, and the
          // loop stopped instead of spinning on a limit it cannot meet.
          expect(usernamesOf(survivor), ['only-copy-of-this']);
        });
      });
    });
  });
}
