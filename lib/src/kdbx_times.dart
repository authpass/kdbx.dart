import 'package:clock/clock.dart';
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

  void modifiedNow() {
    accessedNow();
    lastModificationTime.set(clock.now().toUtc());
  }

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
