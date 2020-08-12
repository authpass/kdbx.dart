import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_binary.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:kdbx/src/kdbx_file.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:path/path.dart' as path;
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
  KdbxEntry.create(KdbxFile file, KdbxGroup parent)
      : isHistoryEntry = false,
        history = [],
        super.create(file.ctx, file, 'Entry', parent) {
    icon.set(KdbxIcon.Key);
  }

  KdbxEntry.read(KdbxReadWriteContext ctx, KdbxGroup parent, XmlElement node,
      {this.isHistoryEntry = false})
      : history = [],
        super.read(ctx, parent, node) {
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
    _binaries.addEntries(node.findElements(KdbxXml.NODE_BINARY).map((el) {
      final key = KdbxKey(el.findElements(KdbxXml.NODE_KEY).single.text);
      final valueNode = el.findElements(KdbxXml.NODE_VALUE).single;
      final ref = valueNode.getAttribute(KdbxXml.ATTR_REF);
      if (ref != null) {
        final refId = int.parse(ref);
        final binary = ctx.binaryById(refId);
        if (binary == null) {
          throw KdbxCorruptedFileException(
              'Unable to find binary with id $refId');
        }
        return MapEntry(key, binary);
      }

      return MapEntry(key, KdbxBinary.readBinaryXml(valueNode, isInline: true));
    }));
    history.addAll(node
            .findElements(KdbxXml.NODE_HISTORY)
            .singleOrNull
            ?.findElements('Entry')
            ?.map((entry) =>
                KdbxEntry.read(ctx, parent, entry, isHistoryEntry: true))
            ?.toList() ??
        []);
  }

  final bool isHistoryEntry;

  final List<KdbxEntry> history;

  @override
  set file(KdbxFile file) {
    super.file = file;
    // TODO this looks like some weird workaround, get rid of the
    // `file` reference.
    for (final historyEntry in history) {
      historyEntry.file = file;
    }
  }

  @override
  void onBeforeModify() {
    super.onBeforeModify();
    history.add(KdbxEntry.read(ctx, parent, toXml())..file = file);
  }

  @override
  XmlElement toXml() {
    final el = super.toXml();
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_STRING);
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_HISTORY);
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_BINARY);
    el.children.addAll(stringEntries.map((stringEntry) {
      final value = XmlElement(XmlName(KdbxXml.NODE_VALUE));
      if (stringEntry.value is ProtectedValue) {
        value.attributes.add(
            XmlAttribute(XmlName(KdbxXml.ATTR_PROTECTED), KdbxXml.VALUE_TRUE));
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
    el.children.addAll(binaryEntries.map((binaryEntry) {
      final key = binaryEntry.key;
      final binary = binaryEntry.value;
      final value = XmlElement(XmlName(KdbxXml.NODE_VALUE));
      if (binary.isInline) {
        binary.saveToXml(value);
      } else {
        final binaryIndex = ctx.findBinaryId(binary);
        value.addAttribute(KdbxXml.ATTR_REF, binaryIndex.toString());
      }
      return XmlElement(XmlName(KdbxXml.NODE_BINARY))
        ..children.addAll([
          XmlElement(XmlName(KdbxXml.NODE_KEY))..children.add(XmlText(key.key)),
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

  final Map<KdbxKey, StringValue> _strings = {};

  final Map<KdbxKey, KdbxBinary> _binaries = {};

  Iterable<MapEntry<KdbxKey, KdbxBinary>> get binaryEntries =>
      _binaries.entries;

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
    modify(() {
      if (value == null) {
        _strings.remove(key);
      } else {
        _strings[key] = value;
      }
    });
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

  set label(String label) => setString(KdbxKey('Title'), PlainValue(label));

  /// Creates a new binary and adds it to this entry.
  KdbxBinary createBinary({
    @required bool isProtected,
    @required String name,
    @required Uint8List bytes,
  }) {
    assert(isProtected != null);
    assert(bytes != null);
    assert(name != null);
    // make sure we don't have a path, just the file name.
    final key = _uniqueBinaryName(path.basename(name));
    final binary = KdbxBinary(
      isInline: false,
      isProtected: isProtected,
      value: bytes,
    );
    modify(() {
      file.ctx.addBinary(binary);
      _binaries[key] = binary;
    });
    return binary;
  }

  void removeBinary(KdbxKey binaryKey) {
    modify(() {
      final binary = _binaries.remove(binaryKey);
      if (binary == null) {
        throw StateError(
            'Trying to remove binary key $binaryKey does not exist.');
      }
      // binary will not be removed (yet) from file, because it will
      // be referenced in history.
    });
  }

  KdbxKey _uniqueBinaryName(String fileName) {
    final lastIndex = fileName.lastIndexOf('.');
    final baseName =
        lastIndex > -1 ? fileName.substring(0, lastIndex) : fileName;
    final ext = lastIndex > -1 ? fileName.substring(lastIndex + 1) : 'ext';
    for (var i = 0; i < 1000; i++) {
      final k = i == 0 ? KdbxKey(fileName) : KdbxKey('$baseName$i.$ext');
      if (!_binaries.containsKey(k)) {
        return k;
      }
    }
    throw StateError('Unable to find unique name for $fileName');
  }

  @override
  String toString() {
    return 'KdbxGroup{uuid=$uuid,name=$label}';
  }
}

extension<T> on Iterable<T> {
  T get singleOrNull => singleWhere((element) => true, orElse: () => null);
}
