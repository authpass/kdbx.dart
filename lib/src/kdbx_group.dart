import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_entry.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:xml/xml.dart';

import 'kdbx_object.dart';

final _logger = Logger('kdbx_group');

class KdbxGroup extends KdbxObject {
  KdbxGroup.create({
    required KdbxReadWriteContext ctx,
    required KdbxGroup? parent,
    required String? name,
  }) : super.create(
          ctx,
          parent?.file,
          KdbxXml.NODE_GROUP,
          parent,
        ) {
    this.name.set(name);
    icon.set(KdbxIcon.Folder);
    expanded.set(true);
  }

  KdbxGroup.read(KdbxReadWriteContext ctx, KdbxGroup? parent, XmlElement node)
      : super.read(ctx, parent, node) {
    node
        .findElements(KdbxXml.NODE_GROUP)
        .map((el) => KdbxGroup.read(ctx, this, el))
        .forEach(_groups.add);
    node
        .findElements('Entry')
        .map((el) => KdbxEntry.read(ctx, this, el))
        .forEach(_entries.add);
  }

  @override
  XmlElement toXml() {
    final el = super.toXml();
    XmlUtils.removeChildrenByName(el, 'Group');
    XmlUtils.removeChildrenByName(el, 'Entry');
    el.children.addAll(groups.map((g) => g.toXml()));
    el.children.addAll(_entries.map((e) => e.toXml()));
    return el;
  }

  /// Returns all groups plus this group itself.
  List<KdbxGroup> getAllGroups() => groups
      .expand((g) => g.getAllGroups())
      .followedBy([this]).toList(growable: false);

  /// Returns all entries of this group and all sub groups.
  List<KdbxEntry> getAllEntries() =>
      getAllGroups().expand((g) => g.entries).toList(growable: false);

  /// Returns all groups and entries. (Including the group itself).
  Iterable<KdbxObject> getAllGroupsAndEntries() => <KdbxObject>[this]
      .followedBy(entries)
      .followedBy(groups.expand((g) => g.getAllGroupsAndEntries()));

  List<KdbxGroup> get groups => List.unmodifiable(_groups);
  final List<KdbxGroup> _groups = [];

  List<KdbxEntry> get entries => List.unmodifiable(_entries);
  final List<KdbxEntry> _entries = [];

  void addEntry(KdbxEntry entry) {
    if (entry.parent != this) {
      throw StateError(
          'Invalid operation. Trying to add entry which is already in another group.');
    }
    assert(_entries.findByUuid(entry.uuid) == null,
        'must not already be in this group.');
    modify(() => _entries.add(entry));
  }

  void addGroup(KdbxGroup group) {
    if (group.parent != this) {
      throw StateError(
          'Invalid operation. Trying to add group which is already in another group.');
    }
    modify(() => _groups.add(group));
  }

  /// returns all parents recursively including this group.
  List<KdbxGroup> get breadcrumbs => [...?parent?.breadcrumbs, this];

  StringNode get name => StringNode(this, 'Name');

  StringNode get notes => StringNode(this, 'Notes');

//  String get name => text('Name') ?? '';
  BooleanNode get expanded => BooleanNode(this, 'IsExpanded');

  StringNode get defaultAutoTypeSequence =>
      StringNode(this, 'DefaultAutoTypeSequence');

  BooleanNode get enableAutoType => BooleanNode(this, 'EnableAutoType');

  BooleanNode get enableSearching => BooleanNode(this, 'EnableSearching');

  UuidNode get lastTopVisibleEntry => UuidNode(this, 'LastTopVisibleEntry');

  @override
  void merge(MergeContext mergeContext, KdbxGroup other) {
    assertSameUuid(other, 'merge');

    if (other.wasModifiedAfter(this)) {
      _logger.finest('merge: other group was modified $uuid');
      _overwriteFrom(mergeContext, other);
    }
    _mergeSubObjects<KdbxGroup>(
      mergeContext,
      _groups,
      other._groups,
      importToHere: (other) =>
          KdbxGroup.create(ctx: ctx, parent: this, name: other.name.get())
            ..forceSetUuid(other.uuid)
            ..let((x) => addGroup(x))
            .._overwriteFrom(mergeContext, other),
    );
    _mergeSubObjects<KdbxEntry>(
      mergeContext,
      _entries,
      other._entries,
      importToHere: (other) => other.cloneInto(this),
    );
    mergeContext.markAsMerged(this);
  }

  void _mergeSubObjects<T extends KdbxObject>(
      MergeContext mergeContext, List<T> me, List<T> other,
      {required T Function(T obj) importToHere}) {
    // possibilities:
    // 1. Not changed at all 👍
    // 2. Deleted in other
    // 3. Deleted in this
    // 4. Modified in other
    // 5. Modified in this
    // 6. Moved in other
    // 7. Moved in this

    for (final otherObj in other) {
      final meObj = me.findByUuid(otherObj.uuid);
      if (meObj == null) {
        // moved or deleted.

        final movedObj = mergeContext.objectIndex[otherObj.uuid];
        if (movedObj == null) {
          // item was created in the other file. we have to import it
          final newMeObject = importToHere(otherObj);
          mergeContext.trackChange(newMeObject, debug: '(was created)');
          newMeObject.merge(mergeContext, otherObj);
        } else {
          // item was moved.
          if (otherObj.wasMovedAfter(movedObj)) {
            // item was moved in the other file, so we have to move it here.
            file.move(movedObj, this);
            mergeContext.trackChange(movedObj, debug: 'moved to another group');
          } else {
            // item was moved in this file, so nothing to do.
          }
          movedObj.merge(mergeContext, otherObj);
        }
      } else {
        meObj.merge(mergeContext, otherObj);
      }
    }
  }

  List<KdbxSubNode<dynamic>> get _overwriteNodes => [
        ...objectNodes,
        name,
        notes,
        expanded,
        defaultAutoTypeSequence,
        enableAutoType,
        enableSearching,
        lastTopVisibleEntry,
      ];

  void _overwriteFrom(MergeContext mergeContext, KdbxGroup other) {
    assertSameUuid(other, 'overwrite');
    overwriteSubNodesFrom(mergeContext, _overwriteNodes, other._overwriteNodes);
    // we should probably check that [lastTopVisibleEntry] is still a
    // valid reference?
    times.overwriteFrom(other.times);
  }

  @override
  String toString() {
    return 'KdbxGroup{uuid=$uuid,name=${name.get()}}';
  }
}

extension KdbxGroupInternal on KdbxGroup {
  void internalRemoveGroup(KdbxGroup group) {
    modify(() {
      if (!_groups.remove(group)) {
        throw StateError('Unable to remove $group from $this (Not found)');
      }
    });
  }

  void internalRemoveEntry(KdbxEntry entry) {
    modify(() {
      if (!_entries.remove(entry)) {
        throw StateError('Unable to remove $entry from $this (Not found)');
      }
    });
  }
}
