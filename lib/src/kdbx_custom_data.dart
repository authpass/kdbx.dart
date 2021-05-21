import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:xml/xml.dart' as xml;
import 'package:kdbx/src/internal/extension_utils.dart';

class KdbxCustomData extends KdbxNode {
  KdbxCustomData.create()
      : _data = {},
        super.create(TAG_NAME);

  KdbxCustomData.read(xml.XmlElement node)
      : _data = Map.fromEntries(
            node.findElements(KdbxXml.NODE_CUSTOM_DATA_ITEM).map((el) {
          final key = el.singleTextNode(KdbxXml.NODE_KEY);
          final value = el.singleTextNode(KdbxXml.NODE_VALUE);
          return MapEntry(key, value);
        })),
        super.read(node);

  static const String TAG_NAME = 'CustomData';

  final Map<String, String> _data;

  Iterable<MapEntry<String, String>> get entries => _data.entries;

  String? operator [](String key) => _data[key];
  void operator []=(String key, String value) {
    modify(() => _data[key] = value);
  }

  bool containsKey(String key) => _data.containsKey(key);

  @override
  xml.XmlElement toXml() {
    final el = super.toXml();
    el.children.clear();
    el.children.addAll(
      _data.entries
          .map((e) => XmlUtils.createNode(KdbxXml.NODE_CUSTOM_DATA_ITEM, [
                XmlUtils.createTextNode(KdbxXml.NODE_KEY, e.key),
                XmlUtils.createTextNode(KdbxXml.NODE_VALUE, e.value),
              ])),
    );
    return el;
  }
}
