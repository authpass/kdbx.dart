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
  /// With [keepNewerLocationChanged] the local [locationChanged] is kept
  /// unless [other] holds a newer one. During a merge the location of an
  /// object is decided separately from its data, so simply taking [other]'s
  /// value would leave an object sitting in one group while claiming the
  /// location time of another - and a later merge, which compares exactly
  /// those times, would then move it back.
  void overwriteFrom(KdbxTimes other, {bool keepNewerLocationChanged = false}) {
    for (final pair in zip([_dataNodes, other._dataNodes])) {
      final me = pair[0];
      final theirs = pair[1];
      me.set(theirs.get());
    }
    final theirLocationChanged = other.locationChanged.get();
    if (!keepNewerLocationChanged) {
      locationChanged.set(theirLocationChanged);
      return;
    }
    final myLocationChanged = locationChanged.get();
    if (myLocationChanged == null ||
        (theirLocationChanged != null &&
            theirLocationChanged.isAfter(myLocationChanged))) {
      locationChanged.set(theirLocationChanged);
    }
  }
}
