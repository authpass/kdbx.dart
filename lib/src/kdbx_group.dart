import 'package:kdbx/src/kdbx_consts.dart';
import 'package:kdbx/src/kdbx_entry.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:meta/meta.dart';
import 'package:xml/xml.dart';

import 'kdbx_object.dart';

class KdbxGroup extends KdbxObject {
  KdbxGroup.create({@required this.parent, @required String name}) : super.create('Group') {
    this.name.set(name);
    icon.set(KdbxIcon.Folder);
    expanded.set(true);
  }

  KdbxGroup.read(this.parent, XmlElement node) : super.read(node) {
    node
        .findElements('Group')
        .map((el) => KdbxGroup.read(this, el))
        .forEach(groups.add);
    node
        .findElements('Entry')
        .map((el) => KdbxEntry.read(this, el))
        .forEach(_entries.add);
  }
  
  XmlElement toXml() {
    final el = node.copy() as XmlElement;
    XmlUtils.removeChildrenByName(el, 'Group');
    XmlUtils.removeChildrenByName(el, 'Entry');
    el.children.addAll(groups.map((g) => g.toXml()));
    el.children.addAll(_entries.map((e) => e.toXml()));
    return el;
  }

  /// Returns all groups plus this group itself.
  List<KdbxGroup> getAllGroups() => groups
      .expand((g) => g.getAllGroups())
      .followedBy([this]).toList(growable: false);

  /// Returns all entries of this group and all sub groups.
  List<KdbxEntry> getAllEntries() =>
      getAllGroups().expand((g) => g.entries).toList(growable: false);

  /// null if this is the root group.
  final KdbxGroup parent;
  final List<KdbxGroup> groups = [];
  List<KdbxEntry> get entries => List.unmodifiable(_entries);
  final List<KdbxEntry> _entries = [];

  void addEntry(KdbxEntry entry) {
    if (entry.parent != this) {
      throw StateError('Invalid operation. Trying to add entry which is already in another group.');
    }
    _entries.add(entry);
    node.children.add(entry.node);
  }

  StringNode get name => StringNode(this, 'Name');
//  String get name => text('Name') ?? '';
  BooleanNode get expanded => BooleanNode(this, 'IsExpanded');
}
