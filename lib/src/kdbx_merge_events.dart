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
/// Not sealed on purpose: later releases will add kinds (conflicts decided
/// by content, deletions refused because of a later edit, reconciled recycle
/// bins, ...), so a `switch` over these needs a default branch.
///
/// Objects are the ones in *this* file - the one `merge` was called on - so
/// a UI can compare them with what it is showing. Deliberately not every
/// change a merge makes: adopting a newer location time without a move, or
/// importing and pruning history revisions, change nothing a user would
/// recognise, and are left out. `MergeContext.changes` still has them.
abstract class MergeEvent {
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
final class MergeObjectAdded extends MergeEvent {
  const MergeObjectAdded(super.object);
}

/// The other file held a newer version of an entry or group, and it replaced
/// ours.
///
/// For an entry, the version it replaced is kept as a history revision.
final class MergeObjectUpdated extends MergeEvent {
  const MergeObjectUpdated(super.object, {required this.keptUnsavedEdit});

  /// Whether the version replaced was an edit not saved yet - the user's own
  /// work, which survives only as a history revision now. Always false for a
  /// group, which has no history.
  final bool keptUnsavedEdit;

  @override
  String toString() =>
      '$runtimeType($object${keptUnsavedEdit ? ', keptUnsavedEdit' : ''})';
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
  const MergeLocalVersionKept(KdbxEntry super.object);

  @override
  KdbxEntry get object => super.object as KdbxEntry;
}

/// The other file moved an entry or group more recently than we did, and it
/// was moved here too.
///
/// Deleting into the recycle bin is such a move, and is reported as one
/// rather than as a [MergeObjectDeleted]: [to] is then the recycle bin, or a
/// group inside it.
final class MergeObjectMoved extends MergeEvent {
  const MergeObjectMoved(super.object, {required this.from, required this.to});

  /// The group it was in before the merge.
  final KdbxGroup? from;

  /// The group it is in now.
  final KdbxGroup to;

  @override
  String toString() => '$runtimeType($object, $from -> $to)';
}

/// The other file had deleted an entry or group, and it was removed here.
///
/// [object] has been taken out of its group, but still holds its data, so a
/// UI can say what went, and close a screen that shows it. The other file
/// records a deletion for every object inside a deleted group as well, so a
/// deleted group brings one event for itself and one for each of those -
/// and since each of those was taken out of *its* group in turn, a deleted
/// group arrives empty.
final class MergeObjectDeleted extends MergeEvent {
  const MergeObjectDeleted(super.object, {required this.deletionTime});

  /// When the deletion happened, as this file records it. For now that is
  /// the time of the merge rather than the other file's deletion time, see
  /// https://github.com/authpass/kdbx.dart/issues/32 and #24.
  final DateTime? deletionTime;
}
