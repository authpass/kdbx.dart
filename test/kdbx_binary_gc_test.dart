import 'dart:convert';

import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

/// The binary pool is rebuilt from what the file still references, on write.
///
/// Nothing used to shrink it. Detaching an attachment deliberately left the
/// bytes for the revisions that still held it, and when those revisions went
/// there was no second pass, so a database could only ever grow — which is how
/// one grew until another client refused to open it (authpass/authpass#427).
void main() {
  final testUtil = TestUtil();

  int poolSize(KdbxFile file) => file.ctx.binariesIterable.length;

  KdbxEntry entryNamed(KdbxFile file, String username) =>
      file.body.rootGroup.getAllEntries().firstWhere(
        (entry) =>
            entry.getString(KdbxKeyCommon.USER_NAME)?.getText() == username,
      );

  group('unreferenced binaries', () {
    test('go once nothing points at them any more', () async {
      final file = testUtil.createEmptyFile();
      final entry = testUtil.createEntry(
        file,
        file.body.rootGroup,
        'user',
        'pass',
      );
      entry.createBinary(
        isProtected: false,
        name: 'attachment.bin',
        bytes: utf8.encode('the attachment'),
      );
      await file.save();
      expect(poolSize(file), 1);

      // Deleting the entry permanently takes its revisions with it, so these
      // bytes are now reachable from nothing at all.
      file.deletePermanently(entry);
      await file.save();

      expect(poolSize(file), 0);
      final reread = await testUtil.saveAndRead(file);
      expect(poolSize(reread), 0);
    });

    test('stay while a revision still holds them', () async {
      final file = testUtil.createEmptyFile();
      final key = KdbxKey('attachment.bin');
      final entry = testUtil.createEntry(
        file,
        file.body.rootGroup,
        'user',
        'pass',
      );
      entry.createBinary(
        isProtected: false,
        name: 'attachment.bin',
        bytes: utf8.encode('the attachment'),
      );
      await file.save();

      entry.removeBinary(key);
      await file.save();

      // Detached from the entry, but the revision taken when it was detached
      // still has it, and that revision is what a user restores from. This is
      // the assertion that stops the collection going too far.
      expect(entry.getBinary(key), isNull);
      expect(poolSize(file), 1);

      final reread = await testUtil.saveAndRead(file);
      final rereadEntry = reread.body.rootGroup.entries.single;
      expect(rereadEntry.getBinary(key), isNull);
      expect(
        utf8.decode(rereadEntry.history.last.getBinary(key)!.value),
        'the attachment',
      );
    });

    test(
      'leave the surviving references pointing at the right bytes',
      () async {
        final file = testUtil.createEmptyFile();
        final doomed = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'doomed',
          'pass',
        );
        doomed.createBinary(
          isProtected: false,
          name: 'first.bin',
          bytes: utf8.encode('first'),
        );
        final survivor = testUtil.createEntry(
          file,
          file.body.rootGroup,
          'survivor',
          'pass',
        );
        survivor.createBinary(
          isProtected: false,
          name: 'second.bin',
          bytes: utf8.encode('second'),
        );
        await file.save();
        expect(poolSize(file), 2);

        // Dropping the one at index 0 moves the survivor's attachment from 1 to
        // 0. Ids are positions in the pool, so writing the shortened pool
        // without re-resolving them would hand back the wrong bytes here, or
        // none at all.
        file.deletePermanently(doomed);
        final reread = await testUtil.saveAndRead(file);

        expect(poolSize(reread), 1);
        expect(
          utf8.decode(
            entryNamed(
              reread,
              'survivor',
            ).getBinary(KdbxKey('second.bin'))!.value,
          ),
          'second',
        );
      },
    );

    test('of two identical attachments, the referenced one stays', () async {
      final file = testUtil.createEmptyFile();
      final doomed = testUtil.createEntry(
        file,
        file.body.rootGroup,
        'doomed',
        'pass',
      );
      doomed.createBinary(
        isProtected: false,
        name: 'first.bin',
        bytes: utf8.encode('identical bytes'),
      );
      final survivor = testUtil.createEntry(
        file,
        file.body.rootGroup,
        'survivor',
        'pass',
      );
      survivor.createBinary(
        isProtected: false,
        name: 'second.bin',
        bytes: utf8.encode('identical bytes'),
      );
      await file.save();

      // Two slots: `createBinary` does not de-duplicate by value, so the pool
      // holds two objects that are byte for byte the same.
      expect(poolSize(file), 2);

      file.deletePermanently(doomed);
      final reread = await testUtil.saveAndRead(file);

      // Retention is by identity, so the twin nothing references is the one
      // that goes, and the survivor is not left pointing at a gap.
      expect(poolSize(reread), 1);
      expect(
        utf8.decode(
          entryNamed(
            reread,
            'survivor',
          ).getBinary(KdbxKey('second.bin'))!.value,
        ),
        'identical bytes',
      );
    });

    test('kdbx3 renumbers the meta pool as well', () async {
      final file = await testUtil.readKdbxFile('test/keepass2binaries.kdbx');
      final original = file.body.rootGroup.entries.first;
      expect(original.binaryEntries, hasLength(3));
      expect(poolSize(file), 3);

      final added = testUtil.createEntry(
        file,
        file.body.rootGroup,
        'added',
        'pass',
      );
      added.createBinary(
        isProtected: false,
        name: 'added.bin',
        bytes: utf8.encode('added'),
      );
      await file.save();

      file.deletePermanently(original);
      final reread = await testUtil.saveAndRead(file);

      // Before kdbx4 the pool lives in Meta/Binaries with explicit ids rather
      // than in the inner header, so this is the other half of the
      // renumbering and it is written by different code.
      expect(poolSize(reread), 1);
      expect(
        utf8.decode(
          entryNamed(reread, 'added').getBinary(KdbxKey('added.bin'))!.value,
        ),
        'added',
      );
    });
  });
}
