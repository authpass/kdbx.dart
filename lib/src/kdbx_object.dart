import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart' show IterableExtension;
import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_file.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_meta.dart';
import 'package:kdbx/src/kdbx_times.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:kdbx/src/utils/sequence.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:quiver/iterables.dart';
import 'package:uuid/data.dart';
import 'package:uuid/rng.dart';
import 'package:uuid/uuid.dart';
import 'package:xml/xml.dart';

// ignore: unused_element
final _logger = Logger('kdbx.kdbx_object');

class ChangeEvent<T> {
  ChangeEvent({required this.object, required this.isDirty});

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

  TimeSequence? _isDirty;

  /// allow recursive calls to [modify]
  bool _isInModify = false;

  /// Called before the *first* modification (ie. before `isDirty` changes
  /// from false to true)
  @protected
  @mustCallSuper
  void onBeforeModify() {}

  /// Called after the *first* modification (ie. after `isDirty` changed
  /// from false to true)
  @protected
  @mustCallSuper
  void onAfterModify() {}

  /// Called after the all modifications
  @protected
  @mustCallSuper
  void onAfterAnyModify() {}

  RET modify<RET>(RET Function() modify) {
    if (isDirty || _isInModify) {
      try {
        return modify();
      } finally {
        _isDirty = TimeSequence.now();
        onAfterAnyModify();
      }
    }
    _isInModify = true;
    onBeforeModify();
    try {
      return modify();
    } finally {
      _isDirty = TimeSequence.now();
      _isInModify = false;
      onAfterModify();
      onAfterAnyModify();
      _controller.add(ChangeEvent(object: this as T, isDirty: isDirty));
    }
  }

  bool clean(TimeSequence savedAt) {
    final dirty = _isDirty;
    if (dirty == null) {
      _logger.warning('clean() called, even though we are not even dirty.');
      return false;
    }
    if (savedAt.isBefore(dirty)) {
      _logger.fine('We got dirty after save was invoked. so we are not clean.');
      return false;
    }
    _isDirty = null;
    _controller.add(ChangeEvent(object: this as T, isDirty: isDirty));
    return true;
  }

  bool get isDirty => _isDirty != null;
}

abstract class KdbxNodeContext implements KdbxNode {
  KdbxReadWriteContext get ctx;
}

abstract class KdbxNode with Changeable<KdbxNode> {
  KdbxNode.create(String nodeName) : node = XmlElement(XmlName(nodeName)) {
    _isDirty = TimeSequence.now();
  }

  KdbxNode.read(this.node);

  /// XML Node used while reading this KdbxNode.
  /// Must NOT be modified. Only copies which are obtained through [toXml].
  /// this node should always represent the original loaded state.
  final XmlElement node;

  //  @protected
  //  String text(String nodeName) => _opt(nodeName)?.text;

  /// must only be called to save this object.
  @mustCallSuper
  XmlElement toXml() {
    return node.copy();
  }
}

extension IterableKdbxObject<T extends KdbxObject> on Iterable<T> {
  T? findByUuid(KdbxUuid uuid) =>
      firstWhereOrNull((element) => element.uuid == uuid);
}

extension KdbxObjectInternal on KdbxObject {
  List<KdbxSubNode<dynamic>> get objectNodes => [
    icon,
    customIconUuid,
  ];

  /// should only be used in internal code, used to clone
  /// from one kdbx file into another. (like merging).
  void forceSetUuid(KdbxUuid uuid) {
    _uuid.set(uuid, force: true);
  }

  void assertSameUuid(KdbxObject other, String debugAction) {
    if (uuid != other.uuid) {
      throw StateError(
        'Uuid of other object does not match current object for $debugAction',
      );
    }
  }

  void overwriteSubNodesFrom(
    OverwriteContext overwriteContext,
    List<KdbxSubNode<dynamic>> myNodes,
    List<KdbxSubNode<dynamic>> otherNodes,
  ) {
    for (final node in zip([myNodes, otherNodes])) {
      final me = node[0];
      final other = node[1];
      if (me.set(other.get())) {
        overwriteContext.trackChange(this, node: me.name);
      }
    }
  }
}

abstract class KdbxObject extends KdbxNode {
  KdbxObject.create(
    this.ctx,
    this._file,
    String nodeName,
    KdbxGroup? parent,
  ) : times = KdbxTimes.create(ctx),
      _parent = parent,
      super.create(nodeName) {
    _uuid.set(KdbxUuid.random());
  }

  KdbxObject.read(this.ctx, KdbxGroup? parent, XmlElement node)
    : times = KdbxTimes.read(node.findElements('Times').single, ctx),
      _parent = parent,
      super.read(node);

  /// the file this object is part of. will be set AFTER loading, etc.
  KdbxFile get file => _file!;
  set file(KdbxFile file) => _file = file;

  /// TODO: We should probably get rid of this `file` reference.
  KdbxFile? _file;

  final KdbxReadWriteContext ctx;

  final KdbxTimes times;

  KdbxUuid get uuid => _uuid.get()!;

  UuidNode get _uuid => UuidNode(this, KdbxXml.NODE_UUID);

  IconNode get icon => IconNode(this, 'IconID');

  UuidNode get customIconUuid => UuidNode(this, 'CustomIconUUID');

  KdbxGroup? get parent => _parent;

  KdbxGroup? _parent;

  late final UuidNode previousParentGroup = UuidNode(
    this,
    'PreviousParentGroup',
  );

  KdbxCustomIcon? get customIcon =>
      customIconUuid.get()?.let((uuid) => file.body.meta.customIcons[uuid]);

  set customIcon(KdbxCustomIcon? icon) {
    if (icon != null) {
      file.body.meta.addCustomIcon(icon);
      customIconUuid.set(icon.uuid);
    } else {
      customIconUuid.set(null);
    }
  }

  // @override
  // void onAfterModify() {
  //   super.onAfterModify();
  //   times.modifiedNow();
  //   // during initial `create` the file will be null.
  //   file?.dirtyObject(this);
  // }

  @override
  void onAfterAnyModify() {
    super.onAfterAnyModify();
    times.modifiedNow();
    // during initial `create` the file will be null.
    _file?.dirtyObject(this);
  }

  bool wasModifiedAfter(KdbxObject other) => times.lastModificationTime
      .get()!
      .isAfter(other.times.lastModificationTime.get()!);

  bool wasMovedAfter(KdbxObject other) =>
      times.locationChanged.get()!.isAfter(other.times.locationChanged.get()!);

  @override
  XmlElement toXml() {
    final el = super.toXml();
    XmlUtils.removeChildrenByName(el, 'Times');
    el.children.add(times.toXml());
    return el;
  }

  @internal
  void internalChangeParent(KdbxGroup? parent) {
    modify(() {
      previousParentGroup.set(_parent?.uuid);
      _parent = parent;
    });
  }

  void merge(MergeContext mergeContext, covariant KdbxObject other);

  bool isInRecycleBin() {
    final targetGroup = file.recycleBin;
    if (targetGroup == null) {
      return false;
    }
    return isInGroup(targetGroup);
  }

  bool isInGroup(KdbxGroup group) {
    final parent = this.parent;
    return parent != null && (parent == group || parent.isInGroup(group));
  }
}

class KdbxUuid {
  const KdbxUuid(this.uuid);

  KdbxUuid.random() : this(base64.encode(Uuid.parse(uuidGenerator.v4())));

  KdbxUuid.fromBytes(Uint8List bytes) : this(base64.encode(bytes));

  /// https://tools.ietf.org/html/rfc4122.html#section-4.1.7
  /// > The nil UUID is special form of UUID that is specified to have all
  ///   128 bits set to zero.
  static const NIL = KdbxUuid('AAAAAAAAAAAAAAAAAAAAAA==');

  static final Uuid uuidGenerator = Uuid(goptions: GlobalOptions(CryptoRNG()));

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
