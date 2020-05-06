import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_file.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';

final _logger = Logger('kdbx_dao');

/// Helper object for accessing and modifing data inside
/// a kdbx file.
extension KdbxDao on KdbxFile {
  KdbxGroup createGroup({
    @required KdbxGroup parent,
    @required String name,
  }) {
    assert(parent != null, name != null);
    final newGroup = KdbxGroup.create(parent: parent, name: name);
    parent.addGroup(newGroup);
    return newGroup;
  }

  KdbxGroup findGroupByUuid(KdbxUuid uuid) =>
      body.rootGroup.getAllGroups().firstWhere((group) => group.uuid == uuid,
          orElse: () =>
              throw StateError('Unable to find group with uuid $uuid'));

  KdbxGroup _createRecycleBin() {
    body.meta.recycleBinEnabled.set(true);
    final group = createGroup(parent: body.rootGroup, name: 'Trash');
    group.icon.set(KdbxIcon.TrashBin);
    group.enableAutoType.set(false);
    group.enableSearching.set(false);
    body.meta.recycleBinUUID.set(group.uuid);
    return group;
  }

  KdbxGroup getRecycleBinOrCreate() {
    return recycleBin ?? _createRecycleBin();
  }

  void deleteGroup(KdbxGroup group) {
    move(group, getRecycleBinOrCreate());
  }

  void deleteEntry(KdbxEntry entry) {
    move(entry, getRecycleBinOrCreate());
  }

  void move(KdbxObject kdbxObject, KdbxGroup toGroup) {
    assert(toGroup != null);
    kdbxObject.times.locationChanged.setToNow();
    if (kdbxObject is KdbxGroup) {
      kdbxObject.parent.internalRemoveGroup(kdbxObject);
      kdbxObject.internalChangeParent(toGroup);
      toGroup.addGroup(kdbxObject);
    } else if (kdbxObject is KdbxEntry) {
      kdbxObject.parent.internalRemoveEntry(kdbxObject);
      kdbxObject.internalChangeParent(toGroup);
      toGroup.addEntry(kdbxObject);
    }
  }
}
