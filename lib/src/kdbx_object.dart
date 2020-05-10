import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/kdbx_file.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_times.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:uuid/uuid.dart';
import 'package:uuid/uuid_util.dart';
import 'package:xml/xml.dart';

// ignore: unused_element
final _logger = Logger('kdbx.kdbx_object');

class ChangeEvent<T> {
  ChangeEvent({this.object, this.isDirty});

  final T object;
  final bool isDirty;

  @override
  String toString() {
    return 'ChangeEvent{object: $object, isDirty: $isDirty}';
  }
}

mixin Changeable<T> {
  final _controller = StreamController<ChangeEvent<T>>.broadcast();

  Stream<ChangeEvent<T>> get changes => _controller.stream;

  bool _isDirty = false;

  set isDirty(bool dirty) {
//    _logger.finest('changing dirty (old:$_isDirty) $dirty');
    _isDirty = dirty;
    _controller.add(ChangeEvent(object: this as T, isDirty: dirty));
  }

  bool get isDirty => _isDirty;
}

abstract class KdbxNodeContext implements KdbxNode {
  KdbxReadWriteContext get ctx;
}

abstract class KdbxNode with Changeable<KdbxNode> {
  KdbxNode.create(String nodeName) : node = XmlElement(XmlName(nodeName)) {
    _isDirty = true;
  }

  KdbxNode.read(this.node);

  final XmlElement node;

//  @protected
//  String text(String nodeName) => _opt(nodeName)?.text;

  /// must only be called to save this object.
  /// will mark this object as not dirty.
  @mustCallSuper
  XmlElement toXml() {
    _isDirty = false;
    final el = node.copy() as XmlElement;
    return el;
  }
}

abstract class KdbxObject extends KdbxNode {
  KdbxObject.create(this.file, String nodeName, KdbxGroup parent)
      : times = KdbxTimes.create(file.ctx),
        _parent = parent,
        super.create(nodeName) {
    _uuid.set(KdbxUuid.random());
  }

  KdbxObject.read(KdbxReadWriteContext ctx, KdbxGroup parent, XmlElement node)
      : times = KdbxTimes.read(node.findElements('Times').single, ctx),
        _parent = parent,
        super.read(node);

  /// the file this object is part of. will be set AFTER loading, etc.
  KdbxFile file;

  final KdbxTimes times;

  KdbxUuid get uuid => _uuid.get();

  UuidNode get _uuid => UuidNode(this, 'UUID');

  IconNode get icon => IconNode(this, 'IconID');

  KdbxGroup get parent => _parent;

  KdbxGroup _parent;

  @override
  set isDirty(bool dirty) {
    if (dirty) {
      times.modifiedNow();
      if (/*!isDirty && */ dirty) {
        // during initial `create` the file will be null.
        file?.dirtyObject(this);
      }
    }
    super.isDirty = dirty;
  }

  @override
  XmlElement toXml() {
    final el = super.toXml();
    XmlUtils.removeChildrenByName(el, 'Times');
    el.children.add(times.toXml());
    return el;
  }

  void internalChangeParent(KdbxGroup parent) {
    _parent = parent;
    isDirty = true;
  }
}

class KdbxUuid {
  const KdbxUuid(this.uuid);

  KdbxUuid.random()
      : this(base64.encode(uuidGenerator.parse(uuidGenerator.v4())));

  /// https://tools.ietf.org/html/rfc4122.html#section-4.1.7
  /// > The nil UUID is special form of UUID that is specified to have all
  ///   128 bits set to zero.
  static const NIL = KdbxUuid('AAAAAAAAAAAAAAAAAAAAAA==');

  static final Uuid uuidGenerator =
      Uuid(options: <String, dynamic>{'grng': UuidUtil.cryptoRNG});

  /// base64 representation of uuid.
  final String uuid;

  Uint8List toBytes() => base64.decode(uuid);

  @override
  String toString() => uuid;

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is KdbxUuid && uuid == other.uuid;

  @override
  int get hashCode => uuid.hashCode;

  /// Whether this is the [NIL] uuid.
  bool get isNil => this == NIL;
}
