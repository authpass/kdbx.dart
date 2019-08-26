import 'package:collection/collection.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:xml/xml.dart';

String _canonicalizeKey(String key) => key?.toLowerCase();

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
  KdbxEntry.read(this.parent, XmlElement node) : super.read(node) {
    strings.addEntries(node.findElements('String').map((el) {
      final key = KdbxKey(el.findElements('Key').single.text);
      final valueNode = el.findElements('Value').single;
      if (valueNode.getAttribute('Protected')?.toLowerCase() == 'true') {
        return MapEntry(key, KdbxFile.protectedValueForNode(valueNode));
      } else {
        return MapEntry(key, PlainValue(valueNode.text));
      }
    }));
  }

  KdbxGroup parent;
  Map<KdbxKey, StringValue> strings = <KdbxKey, StringValue>{};

  String _plainValue(KdbxKey key) {
    final value = strings[key];
    if (value is PlainValue) {
      return value.getText();
    }
    return value?.toString();
  }

  String get label => _plainValue(KdbxKey('Title'));
}
