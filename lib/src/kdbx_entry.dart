import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:xml/xml.dart';

class KdbxEntry extends KdbxObject {
  KdbxEntry.read(this.parent, XmlElement node) : super.read(node) {
    strings = Map.fromEntries(node.findElements('String').map((el) {
      final key = el.findElements('Key').single.text;
      final valueNode = el.findElements('Value').single;
      if (valueNode.getAttribute('Protected')?.toLowerCase() == 'true') {
        return MapEntry(key, KdbxFile.protectedValueForNode(valueNode));
      } else {
        return MapEntry(key, PlainValue(valueNode.text));
      }
    }));
  }

  KdbxGroup parent;
  Map<String, StringValue> strings;
}
