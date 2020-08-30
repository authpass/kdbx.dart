import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:xml/xml.dart';

class KdbxDeletedObject extends KdbxNode implements KdbxNodeContext {
  KdbxDeletedObject.create(this.ctx, KdbxUuid uuid)
      : super.create('DeletedObject') {
    _uuid.set(uuid);
    deletionTime.setToNow();
  }

  KdbxDeletedObject.read(XmlElement node, this.ctx) : super.read(node);

  @override
  final KdbxReadWriteContext ctx;

  KdbxUuid get uuid => _uuid.get();
  UuidNode get _uuid => UuidNode(this, KdbxXml.NODE_UUID);
  DateTimeUtcNode get deletionTime => DateTimeUtcNode(this, 'DeletionTime');
}
