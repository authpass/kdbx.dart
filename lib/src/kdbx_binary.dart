import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:meta/meta.dart';
import 'package:xml/xml.dart';

class KdbxBinary {
  KdbxBinary({this.isInline, this.isProtected, this.value});
  final bool isInline;
  final bool isProtected;
  final Uint8List value;

  static KdbxBinary readBinaryInnerHeader(InnerHeaderField field) {
    final flags = field.bytes[0];
    final isProtected = flags & 0x01 == 0x01;
    final value = Uint8List.sublistView(field.bytes, 1);
    return KdbxBinary(
      isInline: false,
      isProtected: isProtected,
      value: value,
    );
  }

  InnerHeaderField writeToInnerHeader() {
    final writer = WriterHelper();
    final flags = isProtected ? 0x01 : 0x00;
    writer.writeUint8(flags);
    writer.writeBytes(value);
    return InnerHeaderField(
        InnerHeaderFields.Binary, writer.output.takeBytes());
  }

  static KdbxBinary readBinaryXml(XmlElement valueNode,
      {@required bool isInline}) {
    assert(isInline != null);
    final isProtected = valueNode.getAttributeBool(KdbxXml.ATTR_PROTECTED);
    final isCompressed = valueNode.getAttributeBool(KdbxXml.ATTR_COMPRESSED);
    var value = base64.decode(valueNode.text.trim());
    if (isCompressed) {
      value = gzip.decode(value) as Uint8List;
    }
    return KdbxBinary(
      isInline: isInline,
      isProtected: isProtected,
      value: value,
    );
  }

  void saveToXml(XmlElement valueNode) {
    final content = base64.encode(gzip.encode(value));
    valueNode.addAttributeBool(KdbxXml.ATTR_PROTECTED, isProtected);
    valueNode.addAttributeBool(KdbxXml.ATTR_COMPRESSED, true);
    valueNode.children.add(XmlText(content));
  }
}
