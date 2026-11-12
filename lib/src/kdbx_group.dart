import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/internal/content_hash.dart';
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
      .followedBy([this])
      .toList(growable: false);

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
        'Invalid operation. Trying to add entry which is already in another group.',
      );
    }
    if (_entries.findByUuid(entry.uuid) != null) {
      throw KdbxDuplicateUuidException(
        uuid: entry.uuid,
        message:
            'Trying to add an entry which is already in this group. Two live '
            'entries must never share a uuid, see '
            'KdbxDao.mergeDuplicateUuidEntries.',
      );
    }
    modifyStructural(() => _entries.add(entry));
  }

  void addGroup(KdbxGroup group) {
    if (group.parent != this) {
      throw StateError(
        'Invalid operation. Trying to add group which is already in another group.',
      );
    }
    modifyStructural(() => _groups.add(group));
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

    // Where the group lives is decided from `locationChanged`, independently
    // of the data comparison below, so reconcile it in every case.
    mergeLocationChangedFrom(mergeContext, other);
    final theirsIsNewer = other.wasModifiedAfter(this);
    // Changed in the same second on both sides: neither is newer, so the
    // content decides, the same way on every device. A group has no history
    // to keep the losing version in, but both copies at least agree.
    final theirsWinsTie =
        !theirsIsNewer &&
        !wasModifiedAfter(other) &&
        compareContentHashes(other._contentHash, _contentHash) > 0;
    if (theirsIsNewer || theirsWinsTie) {
      _logger.finest('merge: other group was modified $uuid');
      final changesBefore = mergeContext.changes.length;
      modifyAdoptingMergedChange(
        () => _overwriteFrom(mergeContext, other, copyLocationChanged: false),
      );
      // Whether the group is expanded, and which entry was scrolled to, is
      // view state another device happened to save, not an update anyone
      // would want to be told about.
      if (mergeContext.changes
          .skip(changesBefore)
          .any((change) => !_viewStateNodeNames.contains(change.node))) {
        mergeContext.trackEvent(
          MergeObjectUpdated(
            this,
            keptUnsavedEdit: false,
            decidedByContent: theirsWinsTie,
          ),
        );
      }
    }
    _mergeSubObjects<KdbxGroup>(
      mergeContext,
      _groups,
      other._groups,
      importToHere: (other) =>
          KdbxGroup.create(ctx: ctx, parent: this, name: other.name.get())
            ..forceSetUuid(other.uuid)
            ..let((x) => addGroup(x))
            ..let(
              (copy) => copy.modifyAdoptingMergedChange(
                () => copy._overwriteFrom(mergeContext, other),
              ),
            ),
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
    MergeContext mergeContext,
    List<T> me,
    List<T> other, {
    required T Function(T obj) importToHere,
  }) {
    // possibilities:
    // 1. Not changed at all 👍
    // 2. Deleted in other
    // 3. Deleted in this
    // 4. Modified in other
    // 5. Modified in this
    // 6. Moved in other
    // 7. Moved in this

    for (final otherObj in other) {
      if (mergeContext.merged.containsKey(otherObj.uuid)) {
        // the incoming file carries more than one live object with this uuid
        // (see [KdbxFile.duplicateUuidsOnOpen]). we merged the first one, and
        // must not merge another into the same local object.
        mergeContext.trackWarning(
          'Ignoring incoming object with a duplicate uuid '
          '${otherObj.uuid} ($otherObj)',
        );
        continue;
      }
      final meObj = me.findByUuid(otherObj.uuid);
      if (meObj == null) {
        // moved or deleted.

        final movedObj = mergeContext.objectIndex[otherObj.uuid];
        if (movedObj == null) {
          // item was created in the other file. we have to import it
          final newMeObject = importToHere(otherObj);
          mergeContext.trackChange(newMeObject, debug: '(was created)');
          mergeContext.trackEvent(MergeObjectAdded(newMeObject));
          newMeObject.merge(mergeContext, otherObj);
        } else {
          // item was moved.
          if (otherObj.wasMovedAfter(movedObj)) {
            // item was moved in the other file, so we have to move it here.
            // every object in the index is in the tree, so it has a parent -
            // and `file.move` would refuse an object without one anyway.
            final movedFrom = movedObj.parent!;
            file.move(movedObj, this);
            // [KdbxDao.move] stamps the move as happening now, but we are
            // only replaying a move which happened in the other file - keep
            // its time, so that a third copy with an even newer move still
            // wins the next merge.
            movedObj.times.locationChanged.set(
              otherObj.times.locationChanged.get(),
            );
            mergeContext.trackChange(movedObj, debug: 'moved to another group');
            mergeContext.trackEvent(
              MergeObjectMoved(movedObj, from: movedFrom, to: this),
            );
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

  /// The names of the [_overwriteNodes] which only record how the group was
  /// last shown, see [merge].
  static const _viewStateNodeNames = {'IsExpanded', 'LastTopVisibleEntry'};

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

  /// A hash of everything a merge copies from one version of this group to
  /// another, except its modification time, for ordering two versions from
  /// the same second. See `ContentHashBuilder`.
  Uint8List get _contentHash {
    final builder = ContentHashBuilder()..addString('group');
    for (final node in _overwriteNodes) {
      builder
        ..addString(node.name)
        ..addString(node.get()?.toString());
    }
    times.addContentTo(builder);
    return builder.build();
  }

  void _overwriteFrom(
    MergeContext mergeContext,
    KdbxGroup other, {
    bool copyLocationChanged = true,
  }) {
    assertSameUuid(other, 'overwrite');
    overwriteSubNodesFrom(mergeContext, _overwriteNodes, other._overwriteNodes);
    // we should probably check that [lastTopVisibleEntry] is still a
    // valid reference?
    times.overwriteFrom(
      other.times,
      copyLocationChanged: copyLocationChanged,
    );
  }

  @override
  String toString() {
    return 'KdbxGroup{uuid=$uuid,name=${name.get()}}';
  }
}

extension KdbxGroupInternal on KdbxGroup {
  void internalRemoveGroup(KdbxGroup group) {
    modifyStructural(() {
      if (!_groups.remove(group)) {
        throw StateError('Unable to remove $group from $this (Not found)');
      }
    });
  }

  void internalRemoveEntry(KdbxEntry entry) {
    modifyStructural(() {
      if (!_entries.remove(entry)) {
        throw StateError('Unable to remove $entry from $this (Not found)');
      }
    });
  }
}
