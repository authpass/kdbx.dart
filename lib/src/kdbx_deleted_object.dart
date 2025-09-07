import 'package:clock/clock.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';

class KdbxDeletedObject extends KdbxNode implements KdbxNodeContext {
  KdbxDeletedObject.create(this.ctx, KdbxUuid? uuid, [DateTime? now])
    : super.create(NODE_NAME) {
    _uuid.set(uuid);
    deletionTime.set(now ?? clock.now().toUtc());
  }

  KdbxDeletedObject.read(super.node, this.ctx) : super.read();

  static const NODE_NAME = KdbxXml.NODE_DELETED_OBJECT;

  @override
  final KdbxReadWriteContext ctx;

  // all objects have to have a UUID.
  KdbxUuid get uuid => _uuid.get()!;
  UuidNode get _uuid => UuidNode(this, KdbxXml.NODE_UUID);
  DateTimeUtcNode get deletionTime => DateTimeUtcNode(this, 'DeletionTime');
}
