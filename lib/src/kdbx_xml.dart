import 'dart:convert';
import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/utils/byte_utils.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:meta/meta.dart';
import 'package:xml/xml.dart';

class KdbxXml {
  static const NODE_STRING = 'String';
  static const NODE_KEY = 'Key';
  static const NODE_VALUE = 'Value';
  static const ATTR_PROTECTED = 'Protected';
  static const ATTR_COMPRESSED = 'Compressed';
  static const NODE_GROUP = 'Group';
  static const NODE_DELETED_OBJECT = 'DeletedObject';
  static const NODE_DELETED_OBJECTS = 'DeletedObjects';
  static const NODE_HISTORY = 'History';
  static const NODE_BINARIES = 'Binaries';
  static const ATTR_ID = 'ID';
  static const NODE_BINARY = 'Binary';
  static const ATTR_REF = 'Ref';
  static const NODE_CUSTOM_ICONS = 'CustomIcons';

  /// CustomIcons >> Icon
  static const NODE_ICON = 'Icon';

  /// CustomIcons >> Icon >> Data
  static const NODE_DATA = 'Data';

  /// Used for objects UUID and CustomIcons
  static const NODE_UUID = 'UUID';

  static const NODE_CUSTOM_DATA_ITEM = 'Item';

  static const String VALUE_TRUE = 'True';
  static const String VALUE_FALSE = 'False';
}

extension XmlElementKdbx on XmlElement {
  bool getAttributeBool(String name) =>
      getAttribute(name)?.toLowerCase() == 'true';

  void addAttribute(String name, String value) =>
      attributes.add(XmlAttribute(XmlName(name), value));

  void addAttributeBool(String name, bool value) =>
      addAttribute(name, value ? KdbxXml.VALUE_TRUE : KdbxXml.VALUE_FALSE);
}

abstract class KdbxSubNode<T> {
  KdbxSubNode(this.node, this.name);

  final KdbxNode node;
  final String name;

  T get();

  bool set(T value);

  void remove() {
    node.modify(() {
      node.node.children.removeElementsByName(name);
    });
  }
}

extension on List<XmlNode> {
  void removeElementsByName(String name) {
    removeWhere(
        (element) => element is XmlElement && element.name.local == name);
  }
}

abstract class KdbxSubTextNode<T> extends KdbxSubNode<T> {
  KdbxSubTextNode(KdbxNode node, String name) : super(node, name);

  void Function() _onModify;

  @protected
  String encode(T value);

  @protected
  T decode(String value);

  XmlElement _opt(String nodeName) => node.node
      .findElements(nodeName)
      .singleWhere((x) => true, orElse: () => null);

  void setOnModifyListener(void Function() onModify) {
    _onModify = onModify;
  }

  @override
  T get() {
    final textValue = _opt(name)?.text;
    if (textValue == null) {
      return null;
    }
    return decode(textValue);
  }

  @override
  bool set(T value, {bool force = false}) {
    if (get() == value && force != true) {
      return false;
    }
    node.modify(() {
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
    });
    _onModify?.call();
    return true;
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

class KdbxColor {
  const KdbxColor._fromRgbCode(this._rgb) : assert(_rgb != null && _rgb != '');
  const KdbxColor._nullColor() : _rgb = '';

  factory KdbxColor.parse(String rgb) =>
      rgb.isEmpty ? nullColor : KdbxColor._fromRgbCode(rgb);

  static const nullColor = KdbxColor._nullColor();

  final String _rgb;

  bool get isNull => this == nullColor;
}

class ColorNode extends KdbxSubTextNode<KdbxColor> {
  ColorNode(KdbxNode node, String name) : super(node, name);

  @override
  KdbxColor decode(String value) => KdbxColor.parse(value);

  @override
  String encode(KdbxColor value) => value.isNull ? '' : value._rgb;
}

class BooleanNode extends KdbxSubTextNode<bool> {
  BooleanNode(KdbxNode node, String name) : super(node, name);

  @override
  bool decode(String value) {
    switch (value?.toLowerCase()) {
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
  DateTimeUtcNode(KdbxNodeContext node, String name, {this.defaultValue})
      : super(node, name);

  static const EpochSeconds = 62135596800;
  final DateTime Function() defaultValue;

  KdbxReadWriteContext get _ctx => (node as KdbxNodeContext).ctx;
  static final minDate = DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

  bool isAfter(DateTimeUtcNode other) =>
      (get() ?? minDate).isAfter(other.get() ?? minDate);

  void setToNow() {
    set(clock.now().toUtc());
  }

  @override
  DateTime decode(String value) {
    if (value == null) {
      return defaultValue?.call();
    }
    if (value.contains(':')) {
      return DateTime.parse(value);
    }
    // kdbx 4.x uses base64 encoded date.
    final decoded = base64.decode(value);

    final secondsFrom00 = ReaderHelper(decoded).readUint64();

    return DateTime.fromMillisecondsSinceEpoch(
        (secondsFrom00 - EpochSeconds) * 1000,
        isUtc: true);
  }

  @override
  String encode(DateTime value) {
    assert(value.isUtc);
    if (_ctx.versionMajor >= 4) {
      // for kdbx v4 we need to support binary/base64
      final secondsFrom00 =
          (value.millisecondsSinceEpoch ~/ 1000) + EpochSeconds;
      final encoded = base64.encode(
          (WriterHelper()..writeUint64(secondsFrom00)).output.toBytes());
      return encoded;
    }
    return DateTimeUtils.toIso8601StringSeconds(value);
  }
}

class XmlUtils {
  static void removeChildrenByName(XmlNode node, String name) {
    node.children
        .removeWhere((node) => node is XmlElement && node.name.local == name);
  }

  static XmlElement createTextNode(String localName, String value) =>
      createNode(localName, [XmlText(value)]);

  static XmlElement createNode(
    String localName, [
    List<XmlNode> children = const [],
  ]) =>
      XmlElement(XmlName(localName))..children.addAll(children);
}

class DateTimeUtils {
  static String toIso8601StringSeconds(DateTime dateTime) {
    final y = _fourDigits(dateTime.year);
    final m = _twoDigits(dateTime.month);
    final d = _twoDigits(dateTime.day);
    final h = _twoDigits(dateTime.hour);
    final min = _twoDigits(dateTime.minute);
    final sec = _twoDigits(dateTime.second);
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
