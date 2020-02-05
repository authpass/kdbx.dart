import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_custom_data.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:meta/meta.dart';
import 'package:xml/xml.dart' as xml;

class KdbxMeta extends KdbxNode {
  KdbxMeta.create({
    @required String databaseName,
    String generator,
  })  : customData = KdbxCustomData.create(),
        super.create('Meta') {
    this.databaseName.set(databaseName);
    this.generator.set(generator ?? 'kdbx.dart');
  }

  KdbxMeta.read(xml.XmlElement node)
      : customData = node
                .singleElement('CustomData')
                ?.let((e) => KdbxCustomData.read(e)) ??
            KdbxCustomData.create(),
        super.read(node);

  final KdbxCustomData customData;

  StringNode get generator => StringNode(this, 'Generator');

  StringNode get databaseName => StringNode(this, 'DatabaseName');

  Base64Node get headerHash => Base64Node(this, 'HeaderHash');

  BooleanNode get recycleBinEnabled => BooleanNode(this, 'RecycleBinEnabled');

  UuidNode get recycleBinUUID => UuidNode(this, 'RecycleBinUUID');

  DateTimeUtcNode get recycleBinChanged =>
      DateTimeUtcNode(this, 'RecycleBinChanged');

  @override
  xml.XmlElement toXml() => super.toXml()..replaceSingle(customData.toXml());
}
