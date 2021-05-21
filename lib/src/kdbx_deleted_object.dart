import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:xml/xml.dart';

class KdbxDeletedObject extends KdbxNode implements KdbxNodeContext {
  KdbxDeletedObject.create(this.ctx, KdbxUuid? uuid) : super.create(NODE_NAME) {
    _uuid.set(uuid);
    deletionTime.setToNow();
  }

  KdbxDeletedObject.read(XmlElement node, this.ctx) : super.read(node);

  static const NODE_NAME = KdbxXml.NODE_DELETED_OBJECT;

  @override
  final KdbxReadWriteContext ctx;

  KdbxUuid? get uuid => _uuid.get();
  UuidNode get _uuid => UuidNode(this, KdbxXml.NODE_UUID);
  DateTimeUtcNode get deletionTime => DateTimeUtcNode(this, 'DeletionTime');
}
