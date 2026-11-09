import 'package:clock/clock.dart';
import 'package:kdbx/src/kdbx_entry.dart';
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

  void deleteGroup(KdbxGroup group) {
    move(group, getRecycleBinOrCreate());
  }

  void deleteEntry(KdbxEntry entry) {
    move(entry, getRecycleBinOrCreate());
  }

  void move(KdbxObject kdbxObject, KdbxGroup toGroup) {
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
  /// For each affected uuid the entry with the newest last modification time
  /// survives; every other copy is folded into that entry's history and
  /// removed from its group. No [KdbxDeletedObject] is recorded, because the
  /// uuid lives on in the surviving entry - a deletion marker would tell the
  /// next merge to delete the survivor as well.
  ///
  /// This rewrites the user's database and cannot be undone, so only call it
  /// after telling them. The file is left dirty, saving it is up to the
  /// caller.
  ///
  /// Returns the repaired uuids. A uuid shared by something other than two
  /// entries (a group and an entry, say) is logged and left alone - the merge
  /// bug could not produce that, so there is no known-good way to merge them.
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
      final survivor = entries.reduce((a, b) => b.wasModifiedAfter(a) ? b : a);
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
