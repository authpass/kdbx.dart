import 'package:kdbx/src/kdbx_entry.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';

/// Something a merge did to one object, in terms a user can be told about.
///
/// [KdbxFile.merge] returns a `MergeContext` whose `events` lists these, in
/// the order they happened. They are meant for a UI that wants to say what a
/// sync changed - "updated on another device", "deleted on another
/// device", "your newer change was kept" - rather than for deciding whether
/// to save, which is what `KdbxFile.isDirty` is for.
///
/// Not sealed on purpose: later releases will add kinds (reconciled recycle
/// bins, ...), so a `switch` over these needs a default branch. A `base`
/// class all the same, so that only this package defines kinds.
///
/// Objects are the ones in *this* file - the one `merge` was called on - so
/// a UI can compare them with what it is showing. Deliberately not every
/// change a merge makes: adopting a newer location time without a move, or
/// importing and pruning history revisions, change nothing a user would
/// recognise, and are left out. `MergeContext.changes` still has them.
abstract base class MergeEvent {
  const MergeEvent(this.object);

  /// The object in this file the event is about.
  final KdbxObject object;

  /// [object]'s uuid, which identifies it across both files.
  KdbxUuid get uuid => object.uuid;

  @override
  String toString() => '$runtimeType($object)';
}

/// An entry or group that existed only in the other file was copied in.
///
/// Reported for every object copied, so a group created on another device
/// brings one event for itself and one for each entry and group inside it.
///
/// It is also how an object *we* deleted permanently comes back, when the
/// other file changed it after that - its data, or where it is. It was not
/// created elsewhere, but kept by the merge. An object the other file merely
/// still has, unchanged since, does not come back.
final class MergeObjectAdded extends MergeEvent {
  const MergeObjectAdded(super.object);
}

/// The other file held a newer version of an entry or group, and it replaced
/// ours.
///
/// For an entry, the version it replaced is kept as a history revision.
final class MergeObjectUpdated extends MergeEvent {
  const MergeObjectUpdated(
    super.object, {
    required this.keptUnsavedEdit,
    this.decidedByContent = false,
  });

  /// Whether the version replaced was an edit not saved yet - the user's own
  /// work, which survives only as a history revision now. Always false for a
  /// group, which has no history.
  final bool keptUnsavedEdit;

  /// Whether both files changed the object within the same second, so that
  /// neither change was newer and the other file's won by comparing content.
  /// Every copy that merges the two picks the same one, so they agree on it,
  /// but it is a coin toss as far as the user is concerned - for an entry,
  /// the change that lost is the newest history revision.
  final bool decidedByContent;

  @override
  String toString() =>
      '$runtimeType($object'
      '${keptUnsavedEdit ? ', keptUnsavedEdit' : ''}'
      '${decidedByContent ? ', decidedByContent' : ''})';
}

/// Our version of an entry was newer and was kept, while the other file held
/// a version of it we had never seen. That version is kept as a history
/// revision.
///
/// Both sides changed the entry, so this is the one case where a user may
/// want to look: the other device's change is not lost, but it is no longer
/// the current one. A version we already had in our history is not
/// reported - that is the other file simply being behind. Nor is one the
/// history limits dropped again in the same merge, being older than every
/// revision they let us keep: that is most often a version we had and
/// pruned, and there is no revision left to point the user to either way.
final class MergeLocalVersionKept extends MergeEvent {
  const MergeLocalVersionKept(
    KdbxEntry super.object, {
    this.decidedByContent = false,
  });

  @override
  KdbxEntry get object => super.object as KdbxEntry;

  /// Whether both files changed the entry within the same second, so that
  /// neither change was newer and ours won by comparing content, see
  /// [MergeObjectUpdated.decidedByContent].
  final bool decidedByContent;

  @override
  String toString() =>
      '$runtimeType($object${decidedByContent ? ', decidedByContent' : ''})';
}

/// The other file moved an entry or group more recently than we did, and it
/// was moved here too.
///
/// Deleting into the recycle bin is such a move, and is reported as one
/// rather than as a [MergeObjectDeleted]: [to] is then the recycle bin, or a
/// group inside it. Compare [to] with `KdbxMeta.recycleBinUUID` to tell: the
/// file's cached `recycleBin` is not refreshed by a merge yet, so it can name
/// no bin, or the wrong one, after the other file created or changed it.
final class MergeObjectMoved extends MergeEvent {
  const MergeObjectMoved(super.object, {required this.from, required this.to});

  /// The group it was in before the merge.
  final KdbxGroup from;

  /// The group it is in now.
  final KdbxGroup to;

  @override
  String toString() => '$runtimeType($object, $from -> $to)';
}

/// The other file had deleted an entry or group after its last change here,
/// and it was removed.
///
/// [object] has been taken out of its group, but still holds its data, so a
/// UI can say what went, and close a screen that shows it. Changing it now
/// throws `KdbxObjectRemovedException`, and `KdbxDao.restore` brings it
/// back. The other file records a deletion for every object inside a
/// deleted group as well, so a deleted group brings one event for itself
/// and one for each of those - and since each of those was taken out of
/// *its* group in turn, a removed group arrives empty.
///
/// A group goes only when everything in it goes. One holding something the
/// other file did not know of when it deleted the group - created in it or
/// moved into it here - stays, see [MergeDeletionRefused].
final class MergeObjectDeleted extends MergeEvent {
  const MergeObjectDeleted(super.object, {required this.deletionTime});

  /// When the other file deleted it.
  final DateTime? deletionTime;
}

/// The other file had deleted an entry or group, but it changed here after
/// that - its data, or where it is - so it was kept.
///
/// For a group the change can also be inside it: a group stays while it
/// holds anything that stays, such as an entry created in it here, which the
/// other file did not know of when it deleted the group.
///
/// Reported on every merge with that other file until it has merged this one
/// in turn, which brings the object back there too: this file keeps no
/// record of the deletion, so it has nothing to remember the refusal by.
final class MergeDeletionRefused extends MergeEvent {
  const MergeDeletionRefused(super.object, {required this.deletionTime});

  /// When the other file deleted it.
  final DateTime? deletionTime;
}
