import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:xml/xml.dart';

final _logger = Logger('kdbx.kdbx_entry');

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

  @override
  String toString() {
    return 'KdbxKey{key: $key}';
  }
}

class KdbxEntry extends KdbxObject {
  KdbxEntry.create(KdbxFile file, this.parent)
      : isHistoryEntry = false,
        super.create(file, 'Entry') {
    icon.set(KdbxIcon.Key);
  }

  KdbxEntry.read(this.parent, XmlElement node, {this.isHistoryEntry = false})
      : super.read(node) {
    _strings.addEntries(node.findElements(KdbxXml.NODE_STRING).map((el) {
      final key = KdbxKey(el.findElements(KdbxXml.NODE_KEY).single.text);
      final valueNode = el.findElements(KdbxXml.NODE_VALUE).single;
      if (valueNode.getAttribute(KdbxXml.ATTR_PROTECTED)?.toLowerCase() ==
          'true') {
        return MapEntry(key, KdbxFile.protectedValueForNode(valueNode));
      } else {
        return MapEntry(key, PlainValue(valueNode.text));
      }
    }));
  }

  final bool isHistoryEntry;

  List<KdbxEntry> _history;

  List<KdbxEntry> get history => _history ??= (() {
        return _historyElement
            .findElements('Entry')
            .map((entry) => KdbxEntry.read(parent, entry, isHistoryEntry: true))
            .toList();
      })();

  XmlElement get _historyElement => node
          .findElements(KdbxXml.NODE_HISTORY)
          .singleWhere((_) => true, orElse: () {
        final el = XmlElement(XmlName(KdbxXml.NODE_HISTORY));
        node.children.add(el);
        return el;
      });

  @override
  set isDirty(bool newDirty) {
    if (!isDirty && newDirty) {
      final history = _historyElement;
      history.children.add(toXml());
    }
    super.isDirty = newDirty;
  }

  @override
  XmlElement toXml() {
    final el = super.toXml();
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_STRING);
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_HISTORY);
    el.children.removeWhere(
        (e) => e is XmlElement && e.name.local == KdbxXml.NODE_STRING);
    el.children.addAll(stringEntries.map((stringEntry) {
      final value = XmlElement(XmlName(KdbxXml.NODE_VALUE));
      if (stringEntry.value is ProtectedValue) {
        value.attributes
            .add(XmlAttribute(XmlName(KdbxXml.ATTR_PROTECTED), 'True'));
        KdbxFile.setProtectedValueForNode(
            value, stringEntry.value as ProtectedValue);
      } else if (stringEntry.value is StringValue) {
        value.children.add(XmlText(stringEntry.value.getText()));
      }
      return XmlElement(XmlName(KdbxXml.NODE_STRING))
        ..children.addAll([
          XmlElement(XmlName(KdbxXml.NODE_KEY))
            ..children.add(XmlText(stringEntry.key.key)),
          value,
        ]);
    }));
    if (!isHistoryEntry) {
      el.children.add(
        XmlElement(XmlName(KdbxXml.NODE_HISTORY))
          ..children.addAll(history.map((e) => e.toXml())),
      );
    }
    return el;
  }

  KdbxGroup parent;
  final Map<KdbxKey, StringValue> _strings = {};

//  Map<KdbxKey, StringValue> get strings => UnmodifiableMapView(_strings);

  Iterable<MapEntry<KdbxKey, StringValue>> get stringEntries =>
      _strings.entries;

  StringValue getString(KdbxKey key) => _strings[key];

  void setString(KdbxKey key, StringValue value) {
    assert(key != null);
    if (_strings[key] == value) {
      _logger.finest('Value did not change for $key');
      return;
    }
    isDirty = true;
    if (value == null) {
      _strings.remove(key);
    } else {
      _strings[key] = value;
    }
  }

  void renameKey(KdbxKey oldKey, KdbxKey newKey) {
    final value = _strings[oldKey];
    removeString(oldKey);
    _strings[newKey] = value;
  }

  void removeString(KdbxKey key) => setString(key, null);

  String _plainValue(KdbxKey key) {
    final value = _strings[key];
    if (value is PlainValue) {
      return value.getText();
    }
    return value?.toString();
  }

  String get label => _plainValue(KdbxKey('Title'));
}
