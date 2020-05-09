import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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
}
