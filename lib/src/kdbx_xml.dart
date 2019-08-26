import 'dart:convert';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:meta/meta.dart';
import 'package:xml/xml.dart';

abstract class KdbxSubNode<T> {
  KdbxSubNode(this.node, this.name);

  final KdbxNode node;
  final String name;

  T get();

  void set(T value);
}

abstract class KdbxSubTextNode<T> extends KdbxSubNode<T> {
  KdbxSubTextNode(KdbxNode node, String name) : super(node, name);

  @protected
  String encode(T value);

  @protected
  T decode(String value);

  XmlElement _opt(String nodeName) =>
      node.node.findElements(nodeName).singleWhere((x) => true, orElse: () => null);

  @override
  T get() {
    final textValue = _opt(name)?.text;
    if (textValue == null) {
      return null;
    }
    return decode(textValue);
  }

  @override
  void set(T value) {
    final el =
    node.node.findElements(name).singleWhere((x) => true, orElse: () {
      final el = XmlElement(XmlName(name));
      node.node.children.add(el);
      return el;
    });
    el.children.clear();
    if (value == null) {
      return;
    }
    final stringValue = encode(value);
    if (stringValue == null) {
      return;
    }
    el.children.add(XmlText(stringValue));
  }
}

class StringNode extends KdbxSubTextNode<String> {
  StringNode(KdbxNode node, String name) : super(node, name);

  @override
  String decode(String value) => value;

  @override
  String encode(String value) => value;
}

class Base64Node extends KdbxSubTextNode<ByteBuffer> {
  Base64Node(KdbxNode node, String name) : super(node, name);

  @override
  ByteBuffer decode(String value) => base64.decode(value).buffer;

  @override
  String encode(ByteBuffer value) => base64.encode(value.asUint8List());
}

class UuidNode extends KdbxSubTextNode<KdbxUuid> {
  UuidNode(KdbxNode node, String name) : super(node, name);

  @override
  KdbxUuid decode(String value) => KdbxUuid(value);

  @override
  String encode(KdbxUuid value) => value.uuid;
}

class IconNode extends KdbxSubTextNode<KdbxIcon> {
  IconNode(KdbxNode node, String name) : super(node, name);

  @override
  KdbxIcon decode(String value) => KdbxIcon.values[int.tryParse(value)];

  @override
  String encode(KdbxIcon value) => value.index.toString();
}

class BooleanNode extends KdbxSubTextNode<bool> {
  BooleanNode(KdbxNode node, String name) : super(node, name);

  @override
  bool decode(String value) {
    switch (value) {
      case 'null': return null;
      case 'true': return true;
      case 'false': return false;
    }
    throw KdbxCorruptedFileException('Invalid boolean value $value for $name');
  }

  @override
  String encode(bool value) => value ? 'true' : 'false';

}
