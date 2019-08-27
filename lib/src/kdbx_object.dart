import 'dart:convert';
import 'dart:typed_data';

import 'package:kdbx/src/kdbx_times.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:meta/meta.dart';
import 'package:uuid/uuid.dart';
import 'package:uuid/uuid_util.dart';
import 'package:xml/xml.dart';

abstract class KdbxNode {
  KdbxNode.create(String nodeName) : node = XmlElement(XmlName(nodeName));

  KdbxNode.read(this.node);

  final XmlElement node;

//  @protected
//  String text(String nodeName) => _opt(nodeName)?.text;

  KdbxSubTextNode textNode(String nodeName) => StringNode(this, nodeName);

  @mustCallSuper
  XmlElement toXml() {
    final el = node.copy() as XmlElement;
    return el;
  }
}

abstract class KdbxObject extends KdbxNode {
  KdbxObject.create(String nodeName)
      : times = KdbxTimes.create(), super.create(nodeName) {
    _uuid.set(KdbxUuid.random());
  }

  KdbxObject.read(XmlElement node) : times = KdbxTimes.read(node.findElements('Times').single),super.read(node);

  final KdbxTimes times;

  KdbxUuid get uuid => _uuid.get();
  UuidNode get _uuid => UuidNode(this, 'UUID');

  IconNode get icon => IconNode(this, 'IconID');

  @override
  XmlElement toXml() {
    final el = super.toXml();
    XmlUtils.removeChildrenByName(el, 'Times');
    el.children.add(times.toXml());
    return el;
  }
}

class KdbxUuid {
  const KdbxUuid(this.uuid);
  KdbxUuid.random() : this(base64.encode(uuidGenerator.parse(uuidGenerator.v4())));

  static final Uuid uuidGenerator = Uuid(options: <String, dynamic>{
    'grng': UuidUtil.cryptoRNG
  });


  /// base64 representation of uuid.
  final String uuid;

  ByteBuffer toBytes() => base64.decode(uuid).buffer;

  @override
  String toString() => uuid;
}
