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

    test('a merge prunes nothing, however far over the limit', () async {
      await withClock(fakeClock, () async {
        final base = testUtil.createEmptyFile();
        testUtil.createEntry(base, base.body.rootGroup, 'user', 'pass');
        base.body.meta.historyMaxItems.set(-1);

        final fileA = await testUtil.saveAndRead(base);
        final entryA = fileA.body.rootGroup.entries.single;

        // B forks before any of A's edits, so A's revisions exist nowhere
        // else. That is the whole point of the arrangement: merge re-adds
        // whatever the other copy still holds, so pruning a *shared* revision
        // comes straight back and the loss is invisible. What pruning here
        // destroys is precisely the revisions only this copy has.
        final fileB = await testUtil.saveAndRead(fileA);
        final entryB = fileB.body.rootGroup.entries.single;

        for (var i = 1; i <= 5; i++) {
          await editAndSave(fileA, entryA, 'a $i');
        }
        expect(entryA.history, hasLength(5));

        // Later than every one of A's edits, so the merge takes B's side and
        // goes down the incoming-changes path.
        await editAndSave(fileB, entryB, 'b 1');

        fileA.body.meta.historyMaxItems.set(2);
        fileA.merge(fileB);
        // Load-bearing: the merge leaves the entry dirty, and an edit made
        // while it is already dirty amends the pending change instead of
        // taking a revision, so without this the edit below would prune
        // nothing and the test would pass for the wrong reason. Saving is
        // also not supposed to prune, which this checks on the way past.
        await fileA.save();

        // Nothing was deleted, although the entry is now at six revisions
        // against a limit of two. The user synced; they edited nothing. A
        // sync that quietly drops four revisions of a password is not a limit
        // being enforced, it is data loss on a schedule — and because
        // `KdbxMeta.create` has always written a limit, it would have been
        // every database this package made, on its first sync.
        expect(entryA.history, hasLength(6));
        expect(titlesOf(entryA), containsAll(['a 1', 'a 2', 'a 3', 'a 4']));

        // An edit the user actually makes does enforce it.
        await editAndSave(fileA, entryA, 'a 6');
        expect(entryA.history, hasLength(2));
      });
    });

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
