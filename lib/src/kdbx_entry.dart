import 'dart:typed_data';

import 'package:collection/collection.dart' show IterableExtension;
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_binary.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:kdbx/src/kdbx_custom_data.dart';
import 'package:kdbx/src/kdbx_exceptions.dart';
import 'package:kdbx/src/kdbx_file.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:path/path.dart' as path;
import 'package:quiver/check.dart';
import 'package:xml/xml.dart';

final _logger = Logger('kdbx.kdbx_entry');

class KdbxKeyCommon {
  static const KEY_TITLE = 'Title';
  static const KEY_URL = 'URL';
  static const KEY_USER_NAME = 'UserName';
  static const KEY_PASSWORD = 'Password';
  static const KEY_OTP = 'OTPAuth';

  static const KdbxKey TITLE = KdbxKey._(KEY_TITLE, 'title');
  static const KdbxKey URL = KdbxKey._(KEY_URL, 'url');
  static const KdbxKey USER_NAME = KdbxKey._(KEY_USER_NAME, 'username');
  static const KdbxKey PASSWORD = KdbxKey._(KEY_PASSWORD, 'password');
  static const KdbxKey OTP = KdbxKey._(KEY_OTP, 'otpauth');

  static const List<KdbxKey> all = [
    TITLE,
    URL,
    USER_NAME,
    PASSWORD,
    OTP,
  ];
}

// this is called during initialization of [KdbxFormat] to make sure there are
// no typos in the constant declared above.
bool kdbxKeyCommonAssertConsistency() {
  assert(
    (() {
      for (final key in KdbxKeyCommon.all) {
        assert(key.key.toLowerCase() == key._canonicalKey);
      }
      return true;
    })(),
  );
  return true;
}

/// Represents a case insensitive (but case preserving) key.
class KdbxKey {
  KdbxKey(this.key) : _canonicalKey = key.toLowerCase();
  const KdbxKey._(this.key, this._canonicalKey);

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

extension KdbxEntryInternal on KdbxEntry {
  KdbxEntry cloneInto(KdbxGroup otherGroup, {bool toHistoryEntry = false}) =>
      KdbxEntry.create(
          otherGroup.file,
          otherGroup,
          isHistoryEntry: toHistoryEntry,
        )
        ..forceSetUuid(uuid)
        ..let(toHistoryEntry ? (x) => null : otherGroup.addEntry)
        .._overwriteFrom(
          OverwriteContext.noop,
          this,
          includeHistory: !toHistoryEntry,
        );

  List<KdbxSubNode<dynamic>> get _overwriteNodes => [
    ...objectNodes,
    foregroundColor,
    backgroundColor,
    overrideURL,
    tags,
  ];

  void _overwriteFrom(
    OverwriteContext overwriteContext,
    KdbxEntry other, {
    bool includeHistory = false,
  }) {
    // we only support overwriting history, if it is empty.
    checkArgument(
      !includeHistory || history.isEmpty,
      message: 'We can only overwrite with history, if local history is empty.',
    );
    assertSameUuid(other, 'overwrite');
    overwriteSubNodesFrom(
      overwriteContext,
      _overwriteNodes,
      other._overwriteNodes,
    );
    // overwrite all strings
    final stringsDiff = _diffMap(_strings, other._strings);
    if (stringsDiff.isNotEmpty) {
      overwriteContext.trackChange(
        this,
        node: 'strings',
        debug: 'changed: ${stringsDiff.join(',')}',
      );
    }
    _strings.clear();
    _strings.addAll(other._strings);
    // overwrite all binaries
    final newBinaries = other._binaries.map(
      (key, value) => MapEntry(
        key,
        ctx.findBinaryByValue(value) ??
            (value..let((that) => ctx.addBinary(that))),
      ),
    );
    _binaries.clear();
    _binaries.addAll(newBinaries);
    customData.overwriteFrom(other.customData);
    times.overwriteFrom(other.times);
    if (includeHistory) {
      for (final historyEntry in other.history) {
        history.add(historyEntry.cloneInto(parent!, toHistoryEntry: false));
      }
    }
  }

  List<String> _diffMap(Map<Object, Object?> a, Map<Object, Object?> b) {
    final keys = {...a.keys, ...b.keys};
    final ret = <String>[];
    for (final key in keys) {
      if (a[key] != b[key]) {
        ret.add(key.toString());
      }
    }
    return ret;
  }
}

class KdbxEntry extends KdbxObject {
  /// Creates a new entry in the given parent group.
  /// callers are still responsible for calling [parent.addEntry(..)]!
  ///
  /// FIXME: this makes no sense, we should automatically attach this to the parent.
  KdbxEntry.create(
    KdbxFile file,
    KdbxGroup parent, {
    this.isHistoryEntry = false,
  }) : history = [],
       customData = KdbxCustomData.create(),
       super.create(file.ctx, file, 'Entry', parent) {
    icon.set(KdbxIcon.Key);
  }

  KdbxEntry.read(
    KdbxReadWriteContext ctx,
    KdbxGroup? parent,
    XmlElement node, {
    this.isHistoryEntry = false,
  }) : history = [],
       customData =
           node
               .singleElement(KdbxXml.NODE_CUSTOM_DATA)
               ?.let((e) => KdbxCustomData.read(e)) ??
           KdbxCustomData.create(),
       super.read(ctx, parent, node) {
    _strings.addEntries(
      node.findElements(KdbxXml.NODE_STRING).map((el) {
        final key = KdbxKey(el.findElements(KdbxXml.NODE_KEY).single.text);
        final valueNode = el.findElements(KdbxXml.NODE_VALUE).single;
        if (valueNode.getAttribute(KdbxXml.ATTR_PROTECTED)?.toLowerCase() ==
            'true') {
          return MapEntry(key, KdbxFile.protectedValueForNode(valueNode));
        } else {
          return MapEntry(key, PlainValue(valueNode.text));
        }
      }),
    );
    _binaries.addEntries(
      node.findElements(KdbxXml.NODE_BINARY).map((el) {
        final key = KdbxKey(el.findElements(KdbxXml.NODE_KEY).single.text);
        final valueNode = el.findElements(KdbxXml.NODE_VALUE).single;
        final ref = valueNode.getAttribute(KdbxXml.ATTR_REF);
        if (ref != null) {
          final refId = int.parse(ref);
          final binary = ctx.binaryById(refId);
          if (binary == null) {
            throw KdbxCorruptedFileException(
              'Unable to find binary with id $refId',
            );
          }
          return MapEntry(key, binary);
        }

        return MapEntry(
          key,
          KdbxBinary.readBinaryXml(valueNode, isInline: true),
        );
      }),
    );
    history.addAll(
      node
              .findElements(KdbxXml.NODE_HISTORY)
              .singleOrNull
              ?.findElements('Entry')
              .map(
                (entry) =>
                    KdbxEntry.read(ctx, parent, entry, isHistoryEntry: true),
              )
              .toList() ??
          [],
    );
  }

  final bool isHistoryEntry;

  final List<KdbxEntry> history;

  ColorNode get foregroundColor => ColorNode(this, 'ForegroundColor');
  ColorNode get backgroundColor => ColorNode(this, 'BackgroundColor');
  StringNode get overrideURL => StringNode(this, 'OverrideURL');
  StringNode get tags => StringNode(this, 'Tags');

  final KdbxCustomData customData;

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
    history.add(
      KdbxEntry.read(
        ctx,
        parent,
        toXml(),
        isHistoryEntry: true,
      )..file = file,
    );
    _maintainHistory();
  }

  /// Drops the oldest revisions until this entry is inside the limits the
  /// database itself declares.
  ///
  /// Called from [onBeforeModify], which is where KeePass prunes too — its
  /// `PwEntry.MaintainBackups` runs from `CreateBackup`, and nothing in
  /// KeePass prunes on save. That placement is the whole safety property: a
  /// database that has already grown past its limits keeps every revision of
  /// every entry nobody touches, and editing one entry can only shorten that
  /// one entry's history. Pruning on save would instead rewrite the entire
  /// database the first time it was opened by a version that does this.
  ///
  /// Everything that marks an entry dirty gets here, which is more than
  /// editing a field: moving an entry between groups does too, and
  /// `KdbxDao.deleteEntry` is a move to the recycle bin. So sending an entry
  /// to the trash prunes its history on the way.
  ///
  /// [KdbxMeta.historyMaxItems] and [KdbxMeta.historyMaxSize] are read from
  /// the file rather than from a constant, and honoured as KeePass defines
  /// them: negative means unlimited, zero means keep nothing. A limit the file
  /// does not declare at all is treated as unlimited — deleting revisions a
  /// database never asked us to bound is not ours to do. [KdbxMeta.create]
  /// writes 20 items and 10 MiB into every new file, but those are this
  /// package's own defaults, not KeePass's, which are 10 items and 6 MiB.
  void _maintainHistory() {
    final meta = file.body.meta;

    final maxItems = meta.historyMaxItems.get();
    if (maxItems != null && maxItems >= 0) {
      while (history.length > maxItems) {
        _removeOldestHistoryEntry();
      }
    }

    final maxSize = meta.historyMaxSize.get();
    if (maxSize != null && maxSize >= 0) {
      // Re-measured after every removal rather than summed once up front,
      // because [_historySize] charges a shared attachment once: dropping one
      // revision changes what the rest cost. KeePass's `MaintainBackups`
      // re-sums the same way.
      while (history.isNotEmpty && _historySize() > maxSize) {
        _removeOldestHistoryEntry();
      }
    }
  }

  /// Removes and returns the revision modified longest ago.
  ///
  /// Oldest by [KdbxTimes.lastModificationTime] rather than by position, like
  /// KeePass's `RemoveOldestBackup`: [merge] appends revisions it found in
  /// another copy of the file, so list order is not chronological. Ties go to
  /// the lowest index, which is the one added first.
  ///
  /// "Oldest" is therefore only as right as the clock of whatever wrote the
  /// file. A revision dated in the future outlives every real one, and an
  /// entry dated in the past loses the snapshot just taken, since that
  /// snapshot carries the entry's own time. KeePass has both properties, and
  /// clamping to avoid them would change which revision is deleted on a
  /// correct clock too, so this matches KeePass and the tests pin it.
  ///
  /// The caller guarantees [history] is not empty.
  KdbxEntry _removeOldestHistoryEntry() {
    var oldestIndex = 0;
    var oldest = _modifiedAtOrEpoch(history.first);
    for (var i = 1; i < history.length; i++) {
      final candidate = _modifiedAtOrEpoch(history[i]);
      if (candidate.isBefore(oldest)) {
        oldestIndex = i;
        oldest = candidate;
      }
    }
    return history.removeAt(oldestIndex);
  }

  /// A revision that records no modification time counts as the oldest there
  /// is.
  ///
  /// [KdbxTimes.read] backfills that field, so a file read through this
  /// package never reaches this fallback. It is here because the obvious
  /// null handling — skip the null, keep looking — makes a run of untimed
  /// revisions select the *newest* one instead, and this is the code path
  /// that deletes the user's data.
  static DateTime _modifiedAtOrEpoch(KdbxEntry revision) =>
      revision.times.lastModificationTime.get() ??
      DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

  /// Roughly what this entry's history costs, for
  /// [KdbxMeta.historyMaxSize].
  ///
  /// Each distinct attachment is counted once, and the count is seeded with
  /// the attachments the live entry still holds, so those are free. The
  /// file's binary pool keeps one copy of each [KdbxBinary] and a revision
  /// taken by [onBeforeModify] round-trips through
  /// `KdbxReadWriteContext.binaryById`, which hands back the same object — so
  /// twenty revisions of an unchanged attachment are twenty references to one
  /// set of bytes.
  ///
  /// This is where KeePass is deliberately not followed. Its `GetSize` bills
  /// every revision the full length of its attachments, which suits its own
  /// model but here would charge a 3 MiB PDF twenty times against a 10 MiB
  /// limit and discard eighteen revisions to free nothing whatsoever.
  /// KeePassXC de-duplicates, seeded from the current entry, for this same
  /// reason, and that is the behaviour copied here.
  int _historySize() {
    final counted = Set<KdbxBinary>.identity()..addAll(_binaries.values);
    var size = 0;
    for (final revision in history) {
      size += revision._approximateSize(counted);
    }
    return size;
  }

  /// Roughly what this revision adds on top of [counted], whose members it
  /// adds its own attachments to.
  ///
  /// An approximation, and one that cannot be anything else: the two
  /// reference implementations disagree. KeePass's `GetSize` estimates
  /// in-process memory — fixed per-field overheads, characters counted twice
  /// for UTF-16 — while KeePassXC sums attribute, attachment and custom-data
  /// sizes. Neither is the serialized length. This counts string keys and
  /// values plus the bytes of every attachment not already counted, which is
  /// what actually makes a database large.
  ///
  /// Does not serialize to measure, for cost rather than for safety:
  /// [onBeforeModify] already serializes the whole entry once per edit, and
  /// doing it again per revision per removal would be the expensive part of
  /// saving.
  int _approximateSize(Set<KdbxBinary> counted) {
    var size = 0;
    for (final string in _strings.entries) {
      size += string.key.key.length + (string.value?.getText()?.length ?? 0);
    }
    for (final binary in _binaries.values) {
      if (counted.add(binary)) {
        size += binary.value.length;
      }
    }
    return size;
  }

  @override
  XmlElement toXml() {
    final el = super.toXml()..replaceSingle(customData.toXml());
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_STRING);
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_HISTORY);
    XmlUtils.removeChildrenByName(el, KdbxXml.NODE_BINARY);
    el.children.addAll(
      stringEntries.map((stringEntry) {
        final value = XmlElement(XmlName(KdbxXml.NODE_VALUE));
        if (stringEntry.value is ProtectedValue) {
          value.attributes.add(
            XmlAttribute(XmlName(KdbxXml.ATTR_PROTECTED), KdbxXml.VALUE_TRUE),
          );
          KdbxFile.setProtectedValueForNode(
            value,
            stringEntry.value as ProtectedValue?,
          );
        } else if (stringEntry.value is StringValue) {
          value.children.add(XmlText(stringEntry.value!.getText()!));
        }
        return XmlElement(XmlName(KdbxXml.NODE_STRING))
          ..children.addAll([
            XmlElement(XmlName(KdbxXml.NODE_KEY))
              ..children.add(XmlText(stringEntry.key.key)),
            value,
          ]);
      }),
    );
    el.children.addAll(
      binaryEntries.map((binaryEntry) {
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
            XmlElement(XmlName(KdbxXml.NODE_KEY))
              ..children.add(XmlText(key.key)),
            value,
          ]);
      }),
    );
    if (!isHistoryEntry) {
      el.children.add(
        XmlElement(XmlName(KdbxXml.NODE_HISTORY))
          ..children.addAll(history.map((e) => e.toXml())),
      );
    }
    return el;
  }

  final Map<KdbxKey, StringValue?> _strings = {};

  final Map<KdbxKey, KdbxBinary> _binaries = {};

  Iterable<MapEntry<KdbxKey, KdbxBinary>> get binaryEntries =>
      _binaries.entries;

  KdbxBinary? getBinary(KdbxKey key) => _binaries[key];

  //  Map<KdbxKey, StringValue> get strings => UnmodifiableMapView(_strings);

  Iterable<MapEntry<KdbxKey, StringValue?>> get stringEntries =>
      _strings.entries;

  StringValue? getString(KdbxKey key) => _strings[key];

  void setString(KdbxKey key, StringValue? value) {
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

  String? _plainValue(KdbxKey key) {
    final value = _strings[key];
    if (value is PlainValue) {
      return value.getText();
    }
    return value?.toString();
  }

  String? get label =>
      _plainValue(KdbxKeyCommon.TITLE)?.takeUnlessBlank() ??
      _plainValue(KdbxKeyCommon.URL)?.takeUnlessBlank();

  set label(String? label) => setString(KdbxKeyCommon.TITLE, PlainValue(label));

  /// Creates a new binary and adds it to this entry.
  KdbxBinary createBinary({
    required bool isProtected,
    required String name,
    required Uint8List bytes,
  }) {
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
          'Trying to remove binary key $binaryKey does not exist.',
        );
      }
      // binary will not be removed (yet) from file, because it will
      // be referenced in history.
    });
  }

  KdbxKey _uniqueBinaryName(String fileName) {
    final lastIndex = fileName.lastIndexOf('.');
    final baseName = lastIndex > -1
        ? fileName.substring(0, lastIndex)
        : fileName;
    final ext = lastIndex > -1 ? fileName.substring(lastIndex + 1) : 'ext';
    for (var i = 0; i < 1000; i++) {
      final k = i == 0 ? KdbxKey(fileName) : KdbxKey('$baseName$i.$ext');
      if (!_binaries.containsKey(k)) {
        return k;
      }
    }
    throw StateError('Unable to find unique name for $fileName');
  }

  static KdbxEntry? _findHistoryEntry(
    List<KdbxEntry> history,
    DateTime? lastModificationTime,
  ) => history.firstWhereOrNull(
    (history) =>
        history.times.lastModificationTime.get() == lastModificationTime,
  );

  @override
  void merge(MergeContext mergeContext, KdbxEntry other) {
    assertSameUuid(other, 'merge');
    if (other.wasModifiedAfter(this)) {
      _logger.finest('$this has incoming changes.');
      // other object is newer, create new history entry and copy fields.
      modify(() => _overwriteFrom(mergeContext, other));
    } else if (wasModifiedAfter(other)) {
      _logger.finest('$this has outgoing changes.');
      // we are newer. check if the old revision lives on in our history.
      final ourLastModificationTime = times.lastModificationTime.get();
      final historyEntry = _findHistoryEntry(history, ourLastModificationTime);
      if (historyEntry == null) {
        // it seems like we don't know about that state, so we have to add
        // it to history.
        history.add(other.cloneInto(parent!, toHistoryEntry: true));
      }
    } else {
      _logger.finest('$this has no changes.');
    }
    // copy missing history entries.
    for (final otherHistoryEntry in other.history) {
      final meHistoryEntry = _findHistoryEntry(
        history,
        otherHistoryEntry.times.lastModificationTime.get(),
      );
      if (meHistoryEntry == null) {
        mergeContext.trackChange(
          this,
          debug:
              'merge in history '
              '${otherHistoryEntry.times.lastModificationTime.get()}',
        );
        history.add(otherHistoryEntry.cloneInto(parent!, toHistoryEntry: true));
      }
    }
    mergeContext.markAsMerged(this);
  }

  String? debugLabel() => label ?? _plainValue(KdbxKeyCommon.USER_NAME);

  @override
  String toString() {
    return 'KdbxEntry{uuid=$uuid,'
        'name=${debugLabel()}}';
  }
}
