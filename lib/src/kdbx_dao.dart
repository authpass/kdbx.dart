import 'package:clock/clock.dart';
import 'package:kdbx/src/kdbx_entry.dart';
import 'package:kdbx/src/kdbx_file.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';

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
