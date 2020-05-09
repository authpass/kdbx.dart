import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_binary.dart';
import 'package:kdbx/src/kdbx_custom_data.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:meta/meta.dart';
import 'package:xml/xml.dart' as xml;

class KdbxMeta extends KdbxNode {
  KdbxMeta.create({
    @required String databaseName,
    String generator,
  })  : customData = KdbxCustomData.create(),
        binaries = [],
        super.create('Meta') {
    this.databaseName.set(databaseName);
    this.generator.set(generator ?? 'kdbx.dart');
  }

  KdbxMeta.read(xml.XmlElement node)
      : customData = node
                .singleElement('CustomData')
                ?.let((e) => KdbxCustomData.read(e)) ??
            KdbxCustomData.create(),
        binaries = node.singleElement(KdbxXml.NODE_BINARIES)?.let((el) sync* {
          var i = 0;
          for (final binaryNode in el.findElements(KdbxXml.NODE_BINARY)) {
            final id = int.parse(binaryNode.getAttribute(KdbxXml.ATTR_ID));
            if (id != i) {
              throw KdbxCorruptedFileException(
                  'Invalid ID for binary. expected $i, but was $id');
            }
            i++;
            yield KdbxBinary.readBinaryXml(binaryNode, isInline: false);
          }
        })?.toList(),
        super.read(node);

  final KdbxCustomData customData;

  /// only used in Kdbx 3
  final List<KdbxBinary> binaries;

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
