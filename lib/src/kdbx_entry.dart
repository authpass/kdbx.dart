import 'package:collection/collection.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:xml/xml.dart';

/// Represents a case insensitive (but case preserving) key.
class KdbxKey {
  KdbxKey(this.key) : _canonicalKey = key.toLowerCase();

  final String key;
  final String _canonicalKey;

  @override
  bool operator ==(Object other) =>
      other is KdbxKey && _canonicalKey == other._canonicalKey;

  @override
  int get hashCode => _canonicalKey.hashCode;
}

class KdbxEntry extends KdbxObject {
  KdbxEntry.create(this.parent) : super.create('Entry') {
    icon.set(KdbxIcon.Key);
  }

  KdbxEntry.read(this.parent, XmlElement node) : super.read(node) {
    _strings.addEntries(node.findElements('String').map((el) {
      final key = KdbxKey(el.findElements('Key').single.text);
      final valueNode = el.findElements('Value').single;
      if (valueNode.getAttribute('Protected')?.toLowerCase() == 'true') {
        return MapEntry(key, KdbxFile.protectedValueForNode(valueNode));
      } else {
        return MapEntry(key, PlainValue(valueNode.text));
      }
    }));
  }

  @override
  XmlElement toXml() {
    final el = super.toXml();
    el.children.removeWhere((e) => e is XmlElement && e.name.local == 'String');
    el.children.addAll(strings.entries.map((stringEntry) {
      final value = XmlElement(XmlName('Value'));
      if (stringEntry.value is ProtectedValue) {
        value.attributes.add(XmlAttribute(XmlName('Protected'), 'true'));
        KdbxFile.setProtectedValueForNode(
            value, stringEntry.value as ProtectedValue);
      } else {
        value.children.add(XmlText(stringEntry.value.getText()));
      }
      return XmlElement(XmlName('String'))
        ..children.addAll([
          XmlElement(XmlName('Key'))
            ..children.add(XmlText(stringEntry.key.key)),
          value,
        ]);
    }));
    return el;
  }

  KdbxGroup parent;
  final Map<KdbxKey, StringValue> _strings = {};

  Map<KdbxKey, StringValue> get strings => UnmodifiableMapView(_strings);

  void setString(KdbxKey key, StringValue value) {
    _strings[key] = value;
  }

  String _plainValue(KdbxKey key) {
    final value = _strings[key];
    if (value is PlainValue) {
      return value.getText();
    }
    return value?.toString();
  }

  String get label => _plainValue(KdbxKey('Title'));
}
