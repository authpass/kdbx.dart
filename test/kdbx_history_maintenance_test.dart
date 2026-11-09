import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

/// Entry history is bounded by the limits the database itself declares, and
/// the pruning happens when a revision is taken — never on save.
///
/// The clock is faked throughout. "Oldest" is decided by
/// `lastModificationTime`, so revisions taken in the same instant would be
/// ordered arbitrarily and every assertion about *which* revision survived
/// would be a coin toss.
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

        // Past KeePass's default of 20 deliberately: a database that declares
        // no limit does not get one imposed on it, because deleting revisions
        // nobody asked us to bound is not ours to do.
        expect(entry.history, hasLength(21));
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
        });
      },
    );

    test('prunes by historyMaxSize, counting attachments', () async {
      await withClock(fakeClock, () async {
        final (file, entry) = await fileWithCleanEntry();
        file.body.meta.historyMaxItems.set(-1);
        entry.createBinary(
          isProtected: false,
          name: 'attachment.bin',
          bytes: Uint8List(1024),
        );
        await file.save();

        // Every revision carries the 1 KiB attachment, so only two of them fit
        // and the item limit is not what does the pruning here.
        file.body.meta.historyMaxSize.set(2500);

        for (var i = 1; i <= 4; i++) {
          await editAndSave(file, entry, 'title $i');
        }

        expect(entry.history, isNotEmpty);
        expect(entry.history.length, lessThanOrEqualTo(2));
      });
    });
  });
}
