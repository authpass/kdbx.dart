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

  List<KdbxSubNode<dynamic>> get _nodes => [
    creationTime,
    lastModificationTime,
    lastAccessTime,
    expiryTime,
    expires,
    usageCount,
    locationChanged,
  ];

  void overwriteFrom(KdbxTimes other) {
    for (final pair in zip([_nodes, other._nodes])) {
      final me = pair[0];
      final other = pair[1];
      me.set(other.get());
    }
  }
}
