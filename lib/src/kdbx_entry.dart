import 'dart:collection';
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
import 'package:kdbx/src/utils/sequence.dart';
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

  /// Folds [other] - a second live entry which wrongly carries this entry's
  /// uuid - and its history into this entry's history. Revisions this entry
  /// already knows about (same last modification time) are skipped, the same
  /// way [KdbxEntry.merge] decides it.
  ///
  /// [other] itself is left alone; removing it from its group is the caller's
  /// job, see [KdbxDao.mergeDuplicateUuidEntries].
  ///
  /// Appends outside [modify], the way [KdbxEntry.merge] copies history: this
  /// entry's own fields do not change, so it must not collect a history
  /// snapshot of its current state from [onBeforeModify], and - the part that
  /// matters - must not have its lastModificationTime moved to now by
  /// [KdbxObject.onAfterAnyModify], which would make a repaired entry win
  /// every later merge against genuinely newer content on another device. The
  /// file still ends up dirty, from the caller removing [other] from its
  /// group.
  void absorbDuplicate(KdbxEntry other) {
    for (final revision in [...other.history, other]) {
      final lastModified = revision.times.lastModificationTime.get();
      if (KdbxEntry._findHistoryEntry(history, lastModified) != null) {
        continue;
      }
      history.add(revision.cloneInto(parent!, toHistoryEntry: true));
    }
  }

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
    bool copyLocationChanged = true,
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
    times.overwriteFrom(
      other.times,
      copyLocationChanged: copyLocationChanged,
    );
    if (includeHistory) {
      for (final historyEntry in other.history) {
        history.add(historyEntry.cloneInto(parent!, toHistoryEntry: true));
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

  /// Whether a structural change made us dirty without recording a revision,
  /// so the next real modification still has to record one. [onBeforeModify]
  /// is only called while we are clean, so without this the move would
  /// swallow the revision belonging to the change which follows it.
  bool _revisionPending = false;

  @override
  RET modify<RET>(RET Function() modify) {
    // only while we are dirty: once we are clean again [onBeforeModify]
    // records the revision itself.
    if (_revisionPending && isDirty && !isInStructuralChange) {
      _recordRevision();
    }
    return super.modify(modify);
  }

  @override
  bool clean(TimeSequence savedAt) {
    final cleaned = super.clean(savedAt);
    if (cleaned) {
      // the saved state is the new baseline, so there is no revision left
      // to catch up on.
      _revisionPending = false;
    }
    return cleaned;
  }

  @override
  void onBeforeModify() {
    super.onBeforeModify();
    if (isInStructuralChange) {
      // moving an entry does not change it, so it must not create a new
      // revision — but the next change still needs one.
      _revisionPending = true;
      return;
    }
    _recordRevision();
  }

  void _recordRevision() {
    _revisionPending = false;
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

  /// Set only while [merge] is copying incoming changes in, so that the
  /// revision that takes does not prune before both histories have been
  /// brought together. [merge] prunes once at the end instead.
  ///
  /// This is KeePass's `CreateBackup(null)`: it passes no database precisely
  /// so that `MaintainBackups` does not run yet, with the comment "Maintain
  /// at end".
  ///
  /// Does not need to be reentrant: [merge] handles one entry at a time and
  /// the `modify` it wraps is synchronous.
  bool _isMerging = false;

  /// Drops the oldest revisions until this entry is inside the limits the
  /// database itself declares.
  ///
  /// Returns whether it removed anything, because callers outside [modify]
  /// have to mark the entry dirty themselves — see [merge].
  ///
  /// Called from [_recordRevision] — so from every path that takes a
  /// revision, including the catch-up one a structural change defers — and
  /// from the end of [merge]. That is where KeePass prunes too: its
  /// `PwEntry.MaintainBackups` runs from `CreateBackup` and from `MergeIn`,
  /// and nothing in KeePass prunes on save.
  ///
  /// What that placement is meant to buy: a database already past its limits
  /// keeps every revision of every entry nobody touches. Pruning on save
  /// would rewrite the whole database the first time a version that does this
  /// opened it — and since [KdbxMeta.create] has always written a limit into
  /// every new file, that is every database this package ever made.
  ///
  /// [merge] defers it rather than skipping it, via [_isMerging], and prunes
  /// once at the end — and only when the merge actually grew [history].
  ///
  /// Both halves of that matter, and for unrelated reasons.
  ///
  /// *Once at the end*, because pruning as the merge goes does not even hold
  /// the limit it was drawn for. It trims this copy before the loop that
  /// imports the other copy's revisions, and that loop matches by
  /// `lastModificationTime`, so a revision just pruned is no longer there to
  /// match and comes straight back from the other side. The entry ends up over
  /// the limit anyway: the test for this watches it reach four revisions
  /// against a limit of two.
  ///
  /// What the early prune is *not* is more destructive. It keeps a superset of
  /// what pruning at the end keeps, and the proof needs both of these legs: a
  /// surviving revision of *this* copy is among this copy's own newest N (and
  /// so survives a prune that only ever sees this copy), while a surviving
  /// revision of the *other* copy is re-added by the import loop regardless.
  /// Drop either leg and it does not hold — in particular it is not true that
  /// everything in the union's newest N is in this copy's newest N, since the
  /// union contains revisions this copy never had. So pruning at the end
  /// deletes at least as much, and strictly more whenever the re-imports would
  /// have put the entry back over the limit. The superset property is also
  /// modulo ties: the import loop matches on an instant, so a pruned revision
  /// sharing its `lastModificationTime` with a surviving one is not re-added.
  ///
  /// What pruning at the end buys, then, is not revisions — it is that the
  /// limit actually holds afterwards, and that survival is decided by date
  /// rather than by which file a revision happened to arrive in. KeePass
  /// orders it the same way: `MergeIn` calls `CreateBackup(null)` per entry,
  /// unions both histories in `MergeEntryHistory`, and ends with a single
  /// `MaintainBackups()`.
  ///
  /// *Only when the merge grew [history]*, because `KdbxGroup._mergeSubObjects`
  /// calls [merge] for every entry the other copy also has — which in an
  /// ordinary sync is every entry in the database. Pruning unconditionally
  /// would therefore trim an entry that is identical on both sides and that
  /// nobody has edited, purely because a sync happened, which is the mass
  /// rewrite this whole placement exists to avoid.
  ///
  /// Growth rather than "the merge changed the entry" because the two come
  /// apart on the path that matters most: when the entry is already dirty,
  /// `modify` takes its early path and [onBeforeModify] never runs, so the
  /// incoming-changes branch overwrites fields without taking a revision. A
  /// merge of a database with unsaved edits in it — which is the only kind
  /// AuthPass merges, since it merges on a save conflict — would otherwise
  /// prune an entry whose history the merge never touched.
  ///
  /// KeePass does prune database-wide: its `MaintainBackups()` covers every
  /// entry, and `KdbxFile.Read.cs`'s `CommonCleanUpRead` runs it on every open
  /// as well, so that a file written by an application which ignored the limits
  /// cannot stay over them. Note what that open-time call does *not* do,
  /// though — it is annotated `// Don't mark database as modified`, so it
  /// trims in memory and the file is only rewritten if something else dirties
  /// it. We prune only what the merge itself grew, and we do persist that.
  ///
  /// What reaches here is a modification of the entry's own data, and only
  /// that. A move is not one: it goes through [modifyStructural], which
  /// records no revision, so there is nothing to maintain. That matters most
  /// for `KdbxDao.deleteEntry`, which is a move to the recycle bin — sending
  /// an entry to the trash used to prune its history on the way, costing
  /// exactly the history someone would want if they restored it. KeePass
  /// never did that, since `MaintainBackups` runs only from `CreateBackup`,
  /// and now neither do we.
  ///
  /// [KdbxMeta.historyMaxItems] and [KdbxMeta.historyMaxSize] are read from
  /// the file rather than from a constant, and honoured as KeePass defines
  /// them: negative means unlimited, zero means keep nothing. A limit the file
  /// does not declare at all is treated as unlimited — deleting revisions a
  /// database never asked us to bound is not ours to do. That last part is a
  /// deviation: KeePass, KeePassXC and KeePassDX all substitute their own
  /// defaults for an absent limit, so a file written by something that omits
  /// the elements is bounded there and unbounded here. [KdbxMeta.create]
  /// writes 20 items and 10 MiB into every new file, but those are this
  /// package's own defaults, not KeePass's, which are 10 items and 6 MiB.
  bool _maintainHistory() {
    if (_isMerging) {
      return false;
    }
    final meta = file.body.meta;
    var removedAny = false;

    final maxItems = meta.historyMaxItems.get();
    if (maxItems != null && maxItems >= 0) {
      while (history.length > maxItems) {
        _removeOldestHistoryEntry();
        removedAny = true;
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
        removedAny = true;
      }
    }
    return removedAny;
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
  /// correct clock too, so this matches KeePass. Both are pinned by tests, so
  /// a later change to clamp after all has to say so out loud.
  ///
  /// The caller guarantees [history] is not empty.
  KdbxEntry _removeOldestHistoryEntry() {
    var oldestIndex = 0;
    var oldest = _modifiedAtOrMinDate(history.first);
    for (var i = 1; i < history.length; i++) {
      final candidate = _modifiedAtOrMinDate(history[i]);
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
  ///
  /// [DateTimeUtcNode.minDate] is the same substitution
  /// [DateTimeUtcNode.isAfter] already makes, so "missing means oldest" is
  /// this package's existing convention rather than a rule invented here.
  static DateTime _modifiedAtOrMinDate(KdbxEntry revision) =>
      revision.times.lastModificationTime.get() ?? DateTimeUtcNode.minDate;

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
  /// This is a deliberate departure from both reference implementations as
  /// they stand today. KeePass's `GetSize` bills every revision the full
  /// length of its attachments, which suits its own model but here would
  /// charge a 3 MiB PDF twenty times against a 10 MiB limit and discard
  /// eighteen revisions to free nothing whatsoever. KeePassXC did de-duplicate
  /// exactly this way, seeded from the current entry, up to 2.2.x; the
  /// subtraction was dropped by 2.4 and current versions bill per revision as
  /// KeePass does. So the precedent is real but historical, and the reason to
  /// keep it is the pool, not the company.
  ///
  /// Two consequences worth knowing, because the number this produces no
  /// longer resembles either implementation. The seed is per entry while the
  /// pool is per file, so two entries sharing one [KdbxBinary] are each
  /// charged for it and pruning one frees nothing (KeePassXC 2.2.x had the
  /// same limitation). And while an attachment is still attached it is free,
  /// which makes the limit effectively a bound on string bytes — the 10 MiB
  /// default will essentially never fire for an ordinary entry.
  int _historySize() {
    // Keyed by value rather than identity: an *inline* binary is rebuilt by
    // `KdbxEntry.read` for every snapshot, so identity would bill each
    // revision the full attachment again — the exact thing this avoids for
    // pooled ones. [KdbxBinary.valueHashCode] is memoized.
    final counted = HashSet<KdbxBinary>(
      equals: (a, b) => a.valueEqual(b),
      hashCode: (binary) => binary.valueHashCode,
    )..addAll(_binaries.values);
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
  ///
  /// A [ProtectedValue] is measured without decrypting it to a `String`.
  /// Dart strings are immutable, so `getText()` on every revision's password
  /// at every edit would leave copies of them around for the garbage
  /// collector to deal with, which is the thing [ProtectedValue] exists to
  /// avoid. The byte count is what this needs, and the masked buffer is
  /// already the right length. That does mean protected values are counted in
  /// UTF-8 bytes and plain ones in UTF-16 code units — immaterial in an
  /// approximation that does not match either reference implementation
  /// anyway.
  int _approximateSize(Set<KdbxBinary> counted) {
    var size = 0;
    for (final string in _strings.entries) {
      final value = string.value;
      size +=
          string.key.key.length +
          (value is ProtectedValue
              ? value.valueLength
              : (value?.getText()?.length ?? 0));
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
    // Only a merge that grew this entry's history may prune it. Measured
    // rather than flagged, so that a branch added here later cannot forget to
    // say so, and because "grew" and "changed" come apart on the already-dirty
    // path. See [_maintainHistory].
    //
    // Measured across the whole method, including the location reconciliation
    // below: that goes through `modifyStructural`, which deliberately records
    // no revision, so it cannot open this gate on its own.
    final historyLengthBefore = history.length;
    // Where the entry lives is decided from `locationChanged`, independently
    // of the data comparison below, so reconcile it in every case.
    mergeLocationChangedFrom(mergeContext, other);
    if (other.wasModifiedAfter(this)) {
      _logger.finest('$this has incoming changes.');
      // other object is newer, create new history entry and copy fields.
      // The revision is wanted; the pruning [onBeforeModify] would do with it
      // is deferred to the end of this method, once the loop below has brought
      // in the other copy's revisions. See [_maintainHistory].
      _isMerging = true;
      try {
        modify(
          () => _overwriteFrom(
            mergeContext,
            other,
            copyLocationChanged: false,
          ),
        );
      } finally {
        _isMerging = false;
      }
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
    // Both histories are in by now, so the limit applies to their union and
    // picks the newest of both sides by date. Pruning any earlier leaves the
    // entry over the limit, because the loop above re-imports a pruned
    // revision the other copy still holds.
    if (history.length > historyLengthBefore) {
      // Through [modifyStructural], because only the incoming-changes branch
      // above goes through [modify] — the other two just append to [history],
      // so the entry can still be clean here even though the merge changed
      // its history. The change has to reach the file, but it must not stamp
      // [times]: a newer local `lastModificationTime` would win the *next*
      // merge against a remote that never changed again. That is the same
      // reason [mergeLocationChangedFrom] uses it, and it also records no
      // revision of its own, which pruning must not do either.
      //
      // It marks the entry dirty whether or not anything was pruned, which is
      // correct and slightly wider than pruning: a merge that only imported
      // revisions really did change this entry, and before this nothing in
      // that path said so, so such a merge could be dropped unsaved.
      if (modifyStructural(_maintainHistory)) {
        // Tracked, or a merge whose only effect was dropping revisions
        // reports no changes at all and the user is told nothing happened.
        mergeContext.trackChange(
          this,
          debug: 'pruned history to declared limit',
        );
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
