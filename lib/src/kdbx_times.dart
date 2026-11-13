import 'package:clock/clock.dart';
import 'package:kdbx/src/internal/content_hash.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:quiver/iterables.dart';

final _logger = Logger('kdbx_times');

class KdbxTimes extends KdbxNode implements KdbxNodeContext {
  KdbxTimes.create(this.ctx) : super.create('Times') {
    final now = clock.now().toUtc();
    creationTime.set(now);
    lastModificationTime.set(now);
    lastAccessTime.set(now);
    expiryTime.set(now);
    expires.set(false);
    usageCount.set(0);
    locationChanged.set(now);
  }
  KdbxTimes.read(super.node, this.ctx) : super.read() {
    // backward compatibility - there was a bug setting/reading
    // modification, lastAccess and expiryTime. Make sure they are defined.
    final checkDates = {
      lastModificationTime: () => creationTime.get() ?? clock.now().toUtc(),
      lastAccessTime: () => lastModificationTime.get() ?? clock.now().toUtc(),
      expiryTime: () {
        expires.set(false);
        return clock.now().toUtc();
      },
    };
    for (final check in checkDates.entries) {
      if (check.key.get() == null) {
        final val = check.value();
        _logger.warning('${check.key.name} was not defined. setting to $val');
        check.key.set(val);
      }
    }
  }

  @override
  final KdbxReadWriteContext ctx;

  DateTimeUtcNode get creationTime => DateTimeUtcNode(this, 'CreationTime');
  DateTimeUtcNode get lastModificationTime =>
      DateTimeUtcNode(this, 'LastModificationTime');
  DateTimeUtcNode get lastAccessTime => DateTimeUtcNode(this, 'LastAccessTime');
  DateTimeUtcNode get expiryTime => DateTimeUtcNode(this, 'ExpiryTime');
  BooleanNode get expires => BooleanNode(this, 'Expires');
  IntNode get usageCount => IntNode(this, 'UsageCount');
  DateTimeUtcNode get locationChanged =>
      DateTimeUtcNode(this, 'LocationChanged');

  void accessedNow() {
    lastAccessTime.set(clock.now().toUtc());
  }

  /// Stamps a modification as happening now - or, when [after] is given and
  /// now falls in the same second as it or before, one second after [after].
  ///
  /// Times are kept to the second, so without [after] an edit made in the
  /// second of the version it replaces carries that version's time, and a
  /// merge comparing the two cannot tell which came first.
  void modifiedNow({DateTime? after}) {
    accessedNow();
    lastModificationTime.set(nowAfter(after));
  }

  /// Stamps a move as happening now - or one second after the current
  /// [locationChanged], when now is not later than that, the same way
  /// [modifiedNow] stamps an edit. A move on a clock that is behind would
  /// otherwise date the object's location back, where an older move or
  /// deletion elsewhere then beats it.
  void movedNow() {
    locationChanged.set(nowAfter(locationChanged.get()));
  }

  /// The time to stamp a change with that has to come after [after]: now,
  /// or one second after [after] when now does not fall in a later second.
  static DateTime nowAfter(DateTime? after) {
    final now = clock.now().toUtc();
    if (after != null && !_wholeSecond(now).isAfter(_wholeSecond(after))) {
      return _wholeSecond(after).add(const Duration(seconds: 1));
    }
    return now;
  }

  /// Adds the times that are part of an object's content to a content hash:
  /// when it was created, and when it expires if it does.
  ///
  /// Not [lastModificationTime], which a hash is compared alongside of; nor
  /// [lastAccessTime] and [usageCount], which merely viewing an object
  /// changes; nor [locationChanged], which is about where the object is. And
  /// [expiryTime] only while [expires] is set: [KdbxTimes.read] fills in a
  /// missing one with the time of reading, so two devices reading the same
  /// file would otherwise disagree about its content.
  void addContentTo(ContentHashBuilder builder) {
    final expiring = expires.get() ?? false;
    builder
      ..addString(creationTime.get()?.toIso8601String())
      ..addString(expiring ? 'expires' : 'never')
      ..addString(expiring ? expiryTime.get()?.toIso8601String() : null);
  }

  /// [time] cut down to the precision a time is stored with.
  static DateTime _wholeSecond(DateTime time) =>
      DateTime.fromMillisecondsSinceEpoch(
        time.millisecondsSinceEpoch - time.millisecondsSinceEpoch % 1000,
        isUtc: true,
      );

  /// Everything but [locationChanged] - i.e. the times which describe the
  /// data of an object, rather than where it sits in the tree.
  List<KdbxSubNode<dynamic>> get _dataNodes => [
    creationTime,
    lastModificationTime,
    lastAccessTime,
    expiryTime,
    expires,
    usageCount,
  ];

  /// Copies all times from [other].
  ///
  /// Pass `copyLocationChanged: false` when copying *data* onto an object
  /// which keeps its own place in the tree - during a merge, that is. Where
  /// an object sits is decided from [locationChanged] alone, separately from
  /// its data, so a data copy which dragged [locationChanged] along would
  /// leave the object sitting in one group while recording the location time
  /// of another, and a later merge comparing those times would move it back.
  /// See `KdbxObject.mergeLocationChangedFrom`.
  ///
  /// The default copies everything, which is what the object-copy callers
  /// need: for a clone, a history revision or an object imported from the
  /// other file, [other]'s location really is the location being recorded.
  void overwriteFrom(KdbxTimes other, {bool copyLocationChanged = true}) {
    for (final pair in zip([_dataNodes, other._dataNodes])) {
      final me = pair[0];
      final theirs = pair[1];
      me.set(theirs.get());
    }
    if (copyLocationChanged) {
      locationChanged.set(other.locationChanged.get());
    }
  }
}
