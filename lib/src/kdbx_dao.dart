import 'package:clock/clock.dart';
import 'package:collection/collection.dart' show IterableExtension;
import 'package:kdbx/src/kdbx_entry.dart';
import 'package:kdbx/src/kdbx_exceptions.dart';
import 'package:kdbx/src/kdbx_file.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:logging/logging.dart';

final _logger = Logger('kdbx_dao');

/// Helper object for accessing and modifing data inside
/// a kdbx file.
extension KdbxDao on KdbxFile {
  KdbxGroup createGroup({
    required KdbxGroup parent,
    required String name,
  }) {
    final newGroup = KdbxGroup.create(ctx: ctx, parent: parent, name: name);
    parent.addGroup(newGroup);
    return newGroup;
  }

  KdbxGroup findGroupByUuid(KdbxUuid? uuid) =>
      body.rootGroup.getAllGroups().firstWhere(
        (group) => group.uuid == uuid,
        orElse: (() =>
            throw StateError('Unable to find group with uuid $uuid')),
      );

  /// Brings back an entry or group that a merge removed because the other
  /// file had deleted it - for a screen that was showing it, say, and caught
  /// a [KdbxObjectRemovedException].
  ///
  /// It goes into [into], or else the group it was removed from if that is
  /// still in the tree, or else the root group. Its deletion record is
  /// dropped and its location time set after the deletion, so the next merge
  /// keeps it on both sides rather than removing it again. A group comes
  /// back on its own: what was in it was removed separately, and each can
  /// be restored in turn.
  void restore(KdbxObject object, {KdbxGroup? into}) {
    if (object.parent != null) {
      throw StateError('Unable to restore $object, it is still in the tree.');
    }
    final previousParent = object.previousParentGroup.get();
    final target =
        into ??
        body.rootGroup.getAllGroups().firstWhereOrNull(
          (group) => group.uuid == previousParent,
        ) ??
        body.rootGroup;
    final deletedAt = ctx.findDeletedObject(object.uuid)?.deletionTime.get();
    ctx.removeDeletedObject(object.uuid);
    object.internalClearRemovedByMerge();
    object.internalChangeParent(target);
    if (object is KdbxGroup) {
      target.addGroup(object);
    } else if (object is KdbxEntry) {
      target.addEntry(object);
    } else {
      throw StateError('Invalid object type. ${object.runtimeType}');
    }
    // A deletion only wins when it is newer than the last change, so a
    // restore in the very second of the deletion - or on a clock behind the
    // one that deleted it - must not be dated before it.
    final now = clock.now().toUtc();
    object.times.locationChanged.set(
      deletedAt != null && now.isBefore(deletedAt) ? deletedAt : now,
    );
  }

  void deleteGroup(KdbxGroup group) {
    move(group, getRecycleBinOrCreate());
  }

  void deleteEntry(KdbxEntry entry) {
    move(entry, getRecycleBinOrCreate());
  }

  void move(KdbxObject kdbxObject, KdbxGroup toGroup) {
    // An object which is not in the tree any more has nowhere to move from:
    // say so, rather than failing on `parent!` below. A merge which applied
    // an incoming deletion leaves callers holding exactly such an object.
    if (kdbxObject.parent == null) {
      throw StateError(
        'Unable to move object. Object has no parent, already deleted?',
      );
    }
    // Checked before anything is mutated. [KdbxGroup.addEntry] is the *last*
    // step of the move and throws on a uuid which [toGroup] already holds - by
    // then the object is out of its old group, so the throw would leave it in
    // no group at all: unreachable from the root group, not written by
    // [KdbxGroup.toXml], and gone on the next save without so much as a
    // deleted object. Only a file which already carries duplicate uuids can
    // get here (see [KdbxFile.duplicateUuidsOnOpen]), which is exactly the
    // file we must not lose entries from.
    if (kdbxObject is KdbxEntry) {
      final collision = toGroup.entries.findByUuid(kdbxObject.uuid);
      if (collision != null && !identical(collision, kdbxObject)) {
        throw KdbxDuplicateUuidException(
          uuid: kdbxObject.uuid,
          message:
              'Unable to move the entry into "${toGroup.name.get()}", which '
              'already holds another entry with this uuid. Repair the file '
              'first, see KdbxDao.mergeDuplicateUuidEntries.',
        );
      }
    }
    kdbxObject.times.locationChanged.setToNow();
    if (kdbxObject is KdbxGroup) {
      kdbxObject.parent!.internalRemoveGroup(kdbxObject);
      kdbxObject.internalChangeParent(toGroup);
      toGroup.addGroup(kdbxObject);
    } else if (kdbxObject is KdbxEntry) {
      kdbxObject.parent!.internalRemoveEntry(kdbxObject);
      kdbxObject.internalChangeParent(toGroup);
      toGroup.addEntry(kdbxObject);
    }
  }

  /// Repairs a file which carries more than one live entry with the same uuid
  /// - the residue of the merge bug fixed after 2.5.0, see
  /// [KdbxFile.duplicateUuidsOnOpen].
  ///
  /// For each affected uuid one entry survives - the one with the newest last
  /// modification time among those *not* in the recycle bin - and every other
  /// copy is folded into its history and removed from whichever group held it.
  /// The survivor stays in its own group, so where the copies were spread over
  /// several groups the entry disappears from all but one of them; its content
  /// is kept as history either way.
  ///
  /// Those absorbed revisions are held back from the history limits, which
  /// would otherwise reach for them first - they are stamped older than the
  /// survivor's own revisions - and delete the last copy of that content on
  /// the user's next unrelated edit. The exemption lasts until the file is
  /// saved and read again, after which they are ordinary history and bounded
  /// like the rest; by then they are on disk rather than only in the copy
  /// this repair consumed.
  ///
  /// No [KdbxDeletedObject] is recorded, because the uuid lives on in the
  /// surviving entry - a deletion marker would tell the next merge to delete
  /// the survivor as well.
  ///
  /// This rewrites the user's database and cannot be undone, so only call it
  /// after telling them. The file is left dirty, saving it is up to the
  /// caller.
  ///
  /// The repair does not travel. It records no deletion, so a replica which
  /// still carries the duplicates keeps them; merging that replica back brings
  /// no copies in (they are skipped with a warning) but does not clean it up
  /// either. Every device has to be repaired on its own, which is what
  /// [KdbxFile.duplicateUuidsOnOpen] is for.
  ///
  /// Returns the repaired uuids. A uuid which is not shared between entries
  /// only (a group and an entry, say) is logged and left alone - the merge bug
  /// could not produce that, so there is no known-good way to merge them.
  List<KdbxUuid> mergeDuplicateUuidEntries() {
    final repaired = <KdbxUuid>[];
    for (final duplicate in findDuplicateUuidObjects().entries) {
      final objects = duplicate.value;
      final entries = objects.whereType<KdbxEntry>().toList();
      if (entries.length != objects.length) {
        _logger.severe(
          'Not repairing ${duplicate.key}, it is not shared between '
          'entries only: $objects',
        );
        continue;
      }
      // A copy the user threw away must not be elected. Recycle-binning one
      // no longer bumps its lastModificationTime - a move is a change of
      // location, not of the entry - but the trashed copy can still be the
      // newest, by having been the newer one when it was thrown away or by
      // being edited afterwards. And with equal timestamps the reduce below
      // keeps the first, which is just as likely to be the trashed one.
      // Either way the user would be left with their visible entry folded
      // into the history of an entry sitting in the bin.
      final live = entries.where((e) => !e.isInRecycleBin()).toList();
      final survivor = (live.isEmpty ? entries : live).reduce(
        (a, b) => b.wasModifiedAfter(a) ? b : a,
      );
      for (final other in entries) {
        if (other == survivor) {
          continue;
        }
        survivor.absorbDuplicate(other);
        other.parent!.internalRemoveEntry(other);
        other.internalChangeParent(null);
      }
      _logger.info(
        'Repaired ${duplicate.key}: folded ${entries.length - 1} duplicate(s) '
        'into the history of $survivor.',
      );
      repaired.add(duplicate.key);
    }
    return repaired;
  }

  void deletePermanently(KdbxObject kdbxObject) {
    final parent = kdbxObject.parent;
    if (parent == null) {
      throw StateError(
        'Unable to delete object. Object as no parent, already deleted?',
      );
    }
    final now = clock.now().toUtc();
    if (kdbxObject is KdbxGroup) {
      for (final object in kdbxObject.getAllGroupsAndEntries()) {
        ctx.addDeletedObject(object.uuid, now);
      }
      parent.internalRemoveGroup(kdbxObject);
    } else if (kdbxObject is KdbxEntry) {
      ctx.addDeletedObject(kdbxObject.uuid, now);
      parent.internalRemoveEntry(kdbxObject);
    } else {
      throw StateError('Invalid object type. ${kdbxObject.runtimeType}');
    }
    kdbxObject.times.locationChanged.set(now);
    kdbxObject.internalChangeParent(null);
  }
}
