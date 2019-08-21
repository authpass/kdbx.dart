import 'package:kdbx/src/kdbx_entry.dart';
import 'package:xml/xml.dart';

import 'kdbx_object.dart';

final _builder = XmlBuilder();

class KdbxGroup extends KdbxObject {
  KdbxGroup(this.parent) : super.create('Group');

  KdbxGroup.read(this.parent, XmlElement node) : super.read(node) {
    node
        .findElements('Group')
        .map((el) => KdbxGroup.read(this, el))
        .forEach(groups.add);
    node
        .findElements('Entry')
        .map((el) => KdbxEntry.read(this, el))
        .forEach(entries.add);
  }

  /// null if this is the root group.
  final KdbxGroup parent;
  final List<KdbxGroup> groups = [];
  final List<KdbxEntry> entries = [];

  String get name => text('Name') ?? '';
}
