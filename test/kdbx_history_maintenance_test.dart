import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
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

    test('moving an entry to the recycle bin prunes it too', () async {
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

        // Not obviously desirable, but it follows from pruning where KeePass
        // prunes: a move marks the entry dirty, so it takes a revision, so it
        // maintains its history. Written down because it is surprising.
        expect(entry.history, hasLength(2));
      });
    });

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
  });
}
