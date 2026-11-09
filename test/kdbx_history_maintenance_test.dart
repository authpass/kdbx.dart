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
void main() {
  final testUtil = TestUtil();

  var now = DateTime.fromMillisecondsSinceEpoch(0);
  final fakeClock = Clock(() => now);

  setUp(() {
    now = DateTime.fromMillisecondsSinceEpoch(0);
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

    test('prunes the revisions a merge brought in, on the next edit', () async {
      await withClock(fakeClock, () async {
        final base = testUtil.createEmptyFile();
        testUtil.createEntry(base, base.body.rootGroup, 'user', 'pass');
        base.body.meta.historyMaxItems.set(-1);

        final fileA = await testUtil.saveAndRead(base);
        final entryA = fileA.body.rootGroup.entries.single;
        for (var i = 1; i <= 3; i++) {
          await editAndSave(fileA, entryA, 'a $i');
        }

        final fileB = await testUtil.saveAndRead(fileA);
        final entryB = fileB.body.rootGroup.entries.single;
        for (var i = 1; i <= 3; i++) {
          await editAndSave(fileB, entryB, 'b $i');
        }

        fileA.body.meta.historyMaxItems.set(2);
        fileA.merge(fileB);
        await fileA.save();

        // [KdbxFile.merge] appends the other side's revisions outside
        // `modify()`, so the hook never sees them, and saving does not prune
        // either: everything the sync fetched is still here, over the limit.
        expect(entryA.history, hasLength(6));

        await editAndSave(fileA, entryA, 'a 4');

        // The next edit is what enforces the limit, and the revisions the
        // sync fetched go with the rest. That is the limit doing its job
        // rather than a bug, but a user who syncs two devices and then types
        // one character does see it, so it is pinned here rather than left to
        // be discovered. Note the save above is load-bearing: the merge
        // leaves the entry dirty, and an edit made while it is already dirty
        // takes no revision at all.
        expect(entryA.history, hasLength(2));
      });
    });

    group('historyMaxSize', () {
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

          // Every revision carrying the attachment had to go; the one that
          // does not fits.
          expect(titlesOf(entry), ['title 3']);
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
