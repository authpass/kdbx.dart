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

abstract class KdbxNode {
  KdbxNode.create(String nodeName) : node = XmlElement(XmlName(nodeName));
  KdbxNode.read(this.node);

  final XmlElement node;

  @protected
  String text(String nodeName) => _opt(nodeName)?.text;

  XmlElement _opt(String nodeName) =>
      node.findElements(nodeName).singleWhere((x) => true, orElse: () => null);
}

abstract class KdbxObject extends KdbxNode {
  KdbxObject.create(String nodeName)
      : uuid = Uuid().v4(),
        super.create(nodeName);

  KdbxObject.read(XmlElement node) : super.read(node) {
    uuid = node.findElements('UUID').single.text;
  }

  String uuid;
}
