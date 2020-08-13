import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_binary.dart';
import 'package:kdbx/src/kdbx_custom_data.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:meta/meta.dart';
import 'package:quiver/iterables.dart';
import 'package:xml/xml.dart' as xml;
import 'package:xml/xml.dart';

class KdbxMeta extends KdbxNode implements KdbxNodeContext {
  KdbxMeta.create({
    @required String databaseName,
    @required this.ctx,
    String generator,
  })  : customData = KdbxCustomData.create(),
        binaries = [],
        _customIcons = {},
        super.create('Meta') {
    this.databaseName.set(databaseName);
    this.generator.set(generator ?? 'kdbx.dart');
  }

  KdbxMeta.read(xml.XmlElement node, this.ctx)
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
        _customIcons = node
                .singleElement(KdbxXml.NODE_CUSTOM_ICONS)
                ?.let((el) sync* {
                  for (final iconNode in el.findElements(KdbxXml.NODE_ICON)) {
                    yield KdbxCustomIcon(
                        uuid: KdbxUuid(
                            iconNode.singleTextNode(KdbxXml.NODE_UUID)),
                        data: base64.decode(
                            iconNode.singleTextNode(KdbxXml.NODE_DATA)));
                  }
                })
                ?.map((e) => MapEntry(e.uuid, e))
                ?.let((that) => Map.fromEntries(that)) ??
            {},
        super.read(node);

  @override
  final KdbxReadWriteContext ctx;

  final KdbxCustomData customData;

  /// only used in Kdbx 3
  final List<KdbxBinary> binaries;

  final Map<KdbxUuid, KdbxCustomIcon> _customIcons;

  Map<KdbxUuid, KdbxCustomIcon> get customIcons =>
      UnmodifiableMapView(_customIcons);

  void addCustomIcon(KdbxCustomIcon customIcon) {
    if (_customIcons.containsKey(customIcon.uuid)) {
      return;
    }
    modify(() => _customIcons[customIcon.uuid] = customIcon);
  }

  StringNode get generator => StringNode(this, 'Generator');

  StringNode get databaseName => StringNode(this, 'DatabaseName');

  Base64Node get headerHash => Base64Node(this, 'HeaderHash');

  BooleanNode get recycleBinEnabled => BooleanNode(this, 'RecycleBinEnabled');

  UuidNode get recycleBinUUID => UuidNode(this, 'RecycleBinUUID');

  DateTimeUtcNode get recycleBinChanged =>
      DateTimeUtcNode(this, 'RecycleBinChanged');

//  void addCustomIcon

  @override
  xml.XmlElement toXml() {
    final ret = super.toXml()..replaceSingle(customData.toXml());
    XmlUtils.removeChildrenByName(ret, KdbxXml.NODE_BINARIES);
    // with kdbx >= 4 we assume the binaries were already written in the header.
    if (ctx.versionMajor < 4) {
      ret.children.add(
        XmlElement(XmlName(KdbxXml.NODE_BINARIES))
          ..children.addAll(
            enumerate(ctx.binariesIterable).map((indexed) {
              final xmlBinary = XmlUtils.createNode(KdbxXml.NODE_BINARY)
                ..addAttribute(KdbxXml.ATTR_ID, indexed.index.toString());
              indexed.value.saveToXml(xmlBinary);
              return xmlBinary;
            }),
          ),
      );
    }
    XmlUtils.removeChildrenByName(ret, KdbxXml.NODE_CUSTOM_ICONS);
    ret.children.add(
      XmlElement(XmlName(KdbxXml.NODE_CUSTOM_ICONS))
        ..children.addAll(customIcons.values.map(
          (e) => XmlUtils.createNode(KdbxXml.NODE_ICON, [
            XmlUtils.createTextNode(KdbxXml.NODE_UUID, e.uuid.uuid),
            XmlUtils.createTextNode(KdbxXml.NODE_DATA, base64.encode(e.data))
          ]),
        )),
    );
    return ret;
  }
}

class KdbxCustomIcon {
  KdbxCustomIcon({this.uuid, this.data});

  /// uuid of the icon, must be unique within each file.
  final KdbxUuid uuid;

  /// Encoded png data of the image. will be base64 encoded into the kdbx file.
  final Uint8List data;
}
