import 'dart:convert';
import 'dart:typed_data';

import 'package:kdbx/src/kdbx_xml.dart';
import 'package:uuid/uuid.dart';
import 'package:uuid/uuid_util.dart';
import 'package:xml/xml.dart';

class KdbxTimes {
  KdbxTimes.read(this.node);

  XmlElement node;

  DateTime get creationTime => _readTime('CreationTime');

  DateTime _readTime(String nodeName) =>
      DateTime.parse(node.findElements(nodeName).single.text);
}

abstract class KdbxNode {
  KdbxNode.create(String nodeName) : node = XmlElement(XmlName(nodeName));

  KdbxNode.read(this.node);

  final XmlElement node;

//  @protected
//  String text(String nodeName) => _opt(nodeName)?.text;

  KdbxSubTextNode textNode(String nodeName) => StringNode(this, nodeName);

}


abstract class KdbxObject extends KdbxNode {
  KdbxObject.create(String nodeName)
      : super.create(nodeName) {
    _uuid.set(KdbxUuid.random());
  }

  KdbxObject.read(XmlElement node) : super.read(node);

  KdbxUuid get uuid => _uuid.get();
  UuidNode get _uuid => UuidNode(this, 'UUID');

  IconNode get icon => IconNode(this, 'IconID');
}

class KdbxUuid {
  const KdbxUuid(this.uuid);
  KdbxUuid.random() : this(uuidGenerator.v4());

  static final Uuid uuidGenerator = Uuid(options: <String, dynamic>{
    'grng': UuidUtil.cryptoRNG
  });


  /// base64 representation of uuid.
  final String uuid;

  ByteBuffer toBytes() => base64.decode(uuid).buffer;

  @override
  String toString() => uuid;
}
