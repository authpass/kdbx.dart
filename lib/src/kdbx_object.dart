import 'package:meta/meta.dart';
import 'package:uuid/uuid.dart';
import 'package:xml/xml.dart';

class KdbxTimes {
  KdbxTimes.read(this.node);

  XmlElement node;

  DateTime get creationTime => _readTime('CreationTime');

  DateTime _readTime(String nodeName) =>
      DateTime.parse(node.findElements(nodeName).single.text);
}

abstract class KdbxObject {
  KdbxObject.create(String nodeName)
      : uuid = Uuid().v4(),
        node = XmlElement(XmlName(nodeName));

  KdbxObject.read(this.node) {
    uuid = node.findElements('UUID').single.text;
  }

  final XmlElement node;
  String uuid;

  @protected
  String text(String nodeName) => _opt(nodeName)?.text;

  XmlElement _opt(String nodeName) =>
      node.findElements(nodeName).singleWhere((x) => true, orElse: () => null);
}
