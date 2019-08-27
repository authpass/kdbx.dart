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

  XmlElement _opt(String nodeName) => node.node
      .findElements(nodeName)
      .singleWhere((x) => true, orElse: () => null);

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
    node.isDirty = true;
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

  @override
  String toString() {
    return '$runtimeType{${_opt(name)?.text}}';
  }
}

class IntNode extends KdbxSubTextNode<int> {
  IntNode(KdbxNode node, String name) : super(node, name);

  @override
  int decode(String value) => int.tryParse(value);

  @override
  String encode(int value) => value.toString();
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
      case 'null':
        return null;
      case 'true':
        return true;
      case 'false':
        return false;
    }
    throw KdbxCorruptedFileException('Invalid boolean value $value for $name');
  }

  @override
  String encode(bool value) => value ? 'true' : 'false';
}

class DateTimeUtcNode extends KdbxSubTextNode<DateTime> {
  DateTimeUtcNode(KdbxNode node, String name) : super(node, name);

  @override
  DateTime decode(String value) => DateTime.parse(value);

  @override
  String encode(DateTime value) {
    assert(value.isUtc);

    // TODO for kdbx v4 we need to support binary/base64
    return DateTimeUtils.toIso8601StringSeconds(value);
  }
}

class XmlUtils {
  static void removeChildrenByName(XmlNode node, String name) {
    node.children
        .removeWhere((node) => node is XmlElement && node.name.local == name);
  }
}

class DateTimeUtils {
  static String toIso8601StringSeconds(DateTime dateTime) {
    final String y = _fourDigits(dateTime.year);
    final String m = _twoDigits(dateTime.month);
    final String d = _twoDigits(dateTime.hour);
    final String h = _twoDigits(dateTime.hour);
    final String min = _twoDigits(dateTime.minute);
    final String sec = _twoDigits(dateTime.second);
    return '$y-$m-${d}T$h:$min:${sec}Z';
  }

  static String _fourDigits(int n) {
    final absN = n.abs();
    final sign = n < 0 ? '-' : '';
    // ignore: prefer_single_quotes
    if (absN >= 1000) {
      return '$n';
    }
    if (absN >= 100) {
      return '${sign}0$absN';
    }
    if (absN >= 10) {
      return '${sign}00$absN';
    }
    return '${sign}000$absN';
  }

  static String _twoDigits(int n) {
    if (n >= 10) {
      return '$n';
    }
    return '0$n';
  }
}
