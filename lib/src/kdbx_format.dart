import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:collection/collection.dart' show IterableExtension;
import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/key_encrypter_kdf.dart';
import 'package:kdbx/src/crypto/protected_salt_generator.dart';
import 'package:kdbx/src/internal/consts.dart';
import 'package:kdbx/src/internal/crypto_utils.dart';
import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/internal/pointycastle_argon2.dart';
import 'package:kdbx/src/kdbx_deleted_object.dart';
import 'package:kdbx/src/kdbx_entry.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_times.dart';
import 'package:kdbx/src/kdbx_var_dictionary.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:kdbx/src/utils/byte_utils.dart';
import 'package:kdbx/src/utils/sequence.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';
import 'package:quiver/iterables.dart';
import 'package:supercharged_dart/supercharged_dart.dart';
import 'package:xml/xml.dart' as xml;

final _logger = Logger('kdbx.format');

/// Context used during reading and writing.
class KdbxReadWriteContext {
  KdbxReadWriteContext({
    required List<KdbxBinary> binaries,
    required this.header,
  }) : _binaries = binaries,
       _deletedObjects = [];

  static final kdbxContext = Expando<KdbxReadWriteContext>();

  static KdbxReadWriteContext kdbxContextForNode(xml.XmlNode node) {
    final ret = kdbxContext[node.document!];
    if (ret == null) {
      throw StateError('Unable to locate kdbx context for document.');
    }
    return ret;
  }

  static void setKdbxContextForNode(
    xml.XmlNode node,
    KdbxReadWriteContext ctx,
  ) {
    kdbxContext[node.document!] = ctx;
  }

  // TODO make [_binaries] and [_deletedObjects] late init :-)
  @protected
  final List<KdbxBinary> _binaries;
  final List<KdbxDeletedObject> _deletedObjects;

  Iterable<KdbxBinary> get binariesIterable => _binaries;

  final KdbxHeader header;

  int get versionMajor => header.version.major;

  void initContext(
    Iterable<KdbxBinary> binaries,
    Iterable<KdbxDeletedObject> deletedObjects,
  ) {
    _binaries.addAll(binaries);
    _deletedObjects.addAll(deletedObjects);
  }

  KdbxBinary? binaryById(int id) {
    if (id >= _binaries.length) {
      return null;
    }
    return _binaries[id];
  }

  void addBinary(KdbxBinary binary) {
    _binaries.add(binary);
  }

  KdbxBinary? findBinaryByValue(KdbxBinary binary) {
    // TODO create a hashset or map?
    return _binaries.firstWhereOrNull((element) => element.valueEqual(binary));
  }

  /// Finds the id of the given binary, putting it in the pool if it is not
  /// there already.
  ///
  /// A binary an entry holds but the pool does not is not missing data: the
  /// bytes are right there in the entry, so there is nothing to recover and
  /// nothing to refuse. Adding it writes a correct file. Throwing instead —
  /// which this used to do — means the user cannot save their password
  /// database, and because [KdbxEntry.onBeforeModify] serializes the entry to
  /// snapshot a revision, it means they cannot even edit the entry.
  ///
  /// How an entry comes to hold one: [KdbxEntry.create] leaves `addEntry` to
  /// its caller, so an attachment made in between belongs to an entry that
  /// [KdbxBody.referencedBinaries] cannot see, and a save in that window
  /// collects it. The same goes for an entry the application still holds after
  /// `KdbxDao.deletePermanently`.
  ///
  /// Safe to do here because ids are resolved before either pool is written.
  /// [KdbxBody.generateXml] serializes the entries first and `meta.toXml()`
  /// after, which is the kdbx3 pool, and [KdbxHeader.innerHeader] is rebuilt
  /// after `generateXml` returns, which is the kdbx4 one. So a binary added
  /// here still reaches the file in this same save.
  int findBinaryId(KdbxBinary binary) {
    assert(!binary.isInline);
    final id = _binaries.indexOf(binary);
    if (id >= 0) {
      return id;
    }
    _logger.warning(
      'Binary was not in the pool, adding it back. '
      '(${binary.value.length},${binary.isInline})',
    );
    _binaries.add(binary);
    return _binaries.length - 1;
  }

  /// removes the given binary. Does not check if it is still referenced
  /// in any [KdbxEntry]!!
  void removeBinary(KdbxBinary binary) {
    if (!_binaries.remove(binary)) {
      throw KdbxCorruptedFileException(
        'Tried to remove binary which is not in this file.',
      );
    }
  }

  /// Drops every pool binary that [referenced] does not contain, and returns
  /// the ones dropped.
  ///
  /// Membership is by identity, because [findBinaryId] resolves by identity:
  /// two attachments with the same bytes occupy two pool slots, and keeping
  /// the referenced one means keeping that object rather than its twin.
  ///
  /// Dropping a binary an entry still holds is therefore not fatal, only
  /// wasteful: [findBinaryId] puts it back when it comes to resolve it, so
  /// the bytes reach the file anyway. That is the safety net under this
  /// walk — not a reason to widen the walk, but the reason a gap in it costs
  /// a warning rather than data.
  ///
  /// Ids are positional and are resolved while the XML is generated, so
  /// nothing has to be renumbered: whatever stays gets its new index from
  /// [findBinaryId] on the next write. That is also why this has to run
  /// before any of that XML exists.
  List<KdbxBinary> removeUnreferencedBinaries(Set<KdbxBinary> referenced) {
    final removed = <KdbxBinary>[];
    _binaries.removeWhere((binary) {
      if (referenced.contains(binary)) {
        return false;
      }
      removed.add(binary);
      return true;
    });
    return removed;
  }

  void addDeletedObject(KdbxUuid uuid, [DateTime? now]) {
    _deletedObjects.add(KdbxDeletedObject.create(this, uuid, now));
  }

  /// The deletion record for [uuid], if this file holds one.
  KdbxDeletedObject? findDeletedObject(KdbxUuid uuid) =>
      _deletedObjects.firstWhereOrNull((record) => record.uuid == uuid);

  /// Removes every deletion record for [uuid], for an object that is live
  /// again - no file may hold a uuid both live and deleted.
  void removeDeletedObject(KdbxUuid uuid) =>
      _deletedObjects.removeWhere((record) => record.uuid == uuid);
}

class KdbxBody extends KdbxNode {
  KdbxBody.create(this.meta, this.rootGroup) : super.create('KeePassFile') {
    node.children.add(meta.node);
    final rootNode = xml.XmlElement(xml.XmlName('Root'));
    node.children.add(rootNode);
    rootNode.children.add(rootGroup.node);
  }

  KdbxBody.read(
    super.node,
    this.meta,
    this.rootGroup,
  ) : super.read();

  //  final xml.XmlDocument xmlDocument;
  final KdbxMeta meta;
  final KdbxGroup rootGroup;

  @visibleForTesting
  List<KdbxDeletedObject> get deletedObjects => ctx._deletedObjects;

  /// Every binary the entry tree and its revisions still point at.
  ///
  /// Walks the groups recursively — the recycle bin is a group like any other
  /// — and each entry's flat `<History>` of earlier versions of itself.
  ///
  /// A revision is the same class, so it has a `history` of its own, and in
  /// memory that is not always empty: the read constructor fills it
  /// unconditionally, and mutating a revision appends to it. Not recursing
  /// into it rests on history here only ever being appended to, so a
  /// revision's nested list is a snapshot of a prefix of the list above it
  /// and holds nothing that is not also reachable from there.
  ///
  /// Deliberately not on the nested list never being serialized, even though
  /// as of #16 it is not: `KdbxEntry._overwriteFrom(includeHistory: true)`
  /// now clones revisions with `toHistoryEntry: true`, and a history entry's
  /// `toXml` omits its own history. That is a second reason, not the reason —
  /// it holds only while nothing serializes a revision as a live entry again,
  /// whereas the prefix argument holds whatever the writers do.
  ///
  /// If that stops being true — if anything starts reordering or splicing
  /// history — this walk has to recurse.
  Set<KdbxBinary> referencedBinaries() {
    final referenced = Set<KdbxBinary>.identity();
    void collect(KdbxEntry entry) {
      referenced.addAll(entry.binaryEntries.map((binary) => binary.value));
    }

    for (final entry in rootGroup.getAllEntries()) {
      collect(entry);
      entry.history.forEach(collect);
    }
    return referenced;
  }

  Future<void> writeV3(
    WriterHelper writer,
    KdbxFile kdbxFile,
    ProtectedSaltGenerator saltGenerator,
  ) async {
    final xml = generateXml(saltGenerator);
    final xmlBytes = utf8.encode(xml.toXmlString());
    final compressedBytes = (kdbxFile.header.compression == Compression.gzip
        ? KdbxFormat._gzipEncode(xmlBytes)
        : xmlBytes);

    final encrypted = await _encryptV3(kdbxFile, compressedBytes);
    writer.writeBytes(encrypted);
  }

  void writeV4(
    WriterHelper writer,
    KdbxFile kdbxFile,
    ProtectedSaltGenerator saltGenerator,
    _KeysV4 keys,
  ) {
    final bodyWriter = WriterHelper();
    final xml = generateXml(saltGenerator);
    kdbxFile.header.innerHeader.updateBinaries(kdbxFile.ctx.binariesIterable);
    kdbxFile.header.writeInnerHeader(bodyWriter);
    bodyWriter.writeBytes(utf8.encode(xml.toXmlString()));
    final compressedBytes = (kdbxFile.header.compression == Compression.gzip
        ? KdbxFormat._gzipEncode(bodyWriter.output.toBytes())
        : bodyWriter.output.toBytes());
    final encrypted = _encryptV4(
      kdbxFile,
      compressedBytes,
      keys.cipherKey,
    );
    final transformed = kdbxFile.kdbxFormat.hmacBlockTransformerEncrypt(
      keys.hmacKey,
      encrypted,
    );
    writer.writeBytes(transformed);
  }

  Future<Uint8List> _encryptV3(
    KdbxFile kdbxFile,
    Uint8List? compressedBytes,
  ) async {
    final byteWriter = WriterHelper();
    byteWriter.writeBytes(
      kdbxFile.header.fields[HeaderFields.StreamStartBytes]!.bytes,
    );
    HashedBlockReader.writeBlocks(ReaderHelper(compressedBytes), byteWriter);
    final bytes = byteWriter.output.toBytes();

    final masterKey = await KdbxFormat._generateMasterKeyV3(
      kdbxFile.header,
      kdbxFile.credentials,
    );
    final encrypted = KdbxFormat._encryptDataAes(
      masterKey,
      bytes,
      kdbxFile.header.fields[HeaderFields.EncryptionIV]!.bytes,
    );
    return encrypted;
  }

  Uint8List _encryptV4(
    KdbxFile kdbxFile,
    Uint8List? compressedBytes,
    Uint8List cipherKey,
  ) {
    final header = kdbxFile.header;
    final cipher = header.cipher;
    if (cipher == Cipher.aes) {
      _logger.fine('We need AES');
      final result = kdbxFile.kdbxFormat._encryptContentV4Aes(
        header,
        cipherKey,
        compressedBytes!,
      );
      //      _logger.fine('Result: ${ByteUtils.toHexList(result)}');
      return result;
    } else if (cipher == Cipher.chaCha20) {
      _logger.fine('We need chacha20');
      return kdbxFile.kdbxFormat.transformContentV4ChaCha20(
        header,
        compressedBytes!,
        cipherKey,
      );
    } else {
      throw UnsupportedError('Unsupported cipherId $cipher');
    }
  }

  KdbxReadWriteContext get ctx => rootGroup.ctx;

  /// All live objects of this body, grouped by uuid. A healthy file has
  /// exactly one object per uuid; a file which was merged by a release build
  /// of an affected version can carry several (see
  /// [KdbxFile.duplicateUuidsOnOpen]).
  Map<KdbxUuid, List<KdbxObject>> _createObjectIndexWithDuplicates() {
    final ret = <KdbxUuid, List<KdbxObject>>{};
    for (final obj in concat([
      rootGroup.getAllGroups(),
      rootGroup.getAllEntries(),
    ])) {
      (ret[obj.uuid] ??= []).add(obj);
    }
    return ret;
  }

  /// The first object for each uuid, in depth-first order. Which copy of a
  /// duplicated uuid this picks is arbitrary either way; taking the first just
  /// makes it deterministic, where `Map.fromEntries` used to keep whichever
  /// came last.
  Map<KdbxUuid, KdbxObject> _createObjectIndex() => {
    for (final e in _createObjectIndexWithDuplicates().entries) ...{
      e.key: e.value.first,
    },
  };

  /// Merges [other] into this file. Deletion is decided in three phases:
  ///
  /// 1. **Records.** The other file's deletion records join ours, with the
  ///    time the other file recorded - a record for a uuid we hold one for
  ///    as well keeps the later of the two times, so both copies agree.
  ///    Except the records of an object either file also holds live, which
  ///    are void and leave both, see [_liveAndDeleted].
  /// 2. **Trees.** The trees are merged as if nothing were deleted, except
  ///    that an object only the other file has, and which a record says was
  ///    deleted after its last change, is not copied in - see
  ///    [MergeContext.wouldOnlyBeRemoved]. That is a copy that is merely
  ///    behind, and taking its objects in only to remove them again would
  ///    make every such merge a change.
  /// 3. **Verdicts,** children first, see [_applyDeletions].
  MergeContext merge(KdbxBody other) {
    final revived = _liveAndDeleted(other);
    final droppedHere = {
      for (final uuid in revived.keys)
        if (ctx.findDeletedObject(uuid) != null) ...{
          uuid,
        },
    };
    droppedHere.forEach(ctx.removeDeletedObject);

    // sync deleted objects.
    // A file can hold more than one record for a uuid - `deletePermanently`
    // used to write one for an object already out of the tree. The later
    // one decides, whatever the order: both copies must pick alike.
    final deleted = <KdbxUuid?, KdbxDeletedObject>{};
    for (final record in ctx._deletedObjects) {
      final known = deleted[record.uuid];
      if (known == null || record.deletionTime.isAfter(known.deletionTime)) {
        deleted[record.uuid] = record;
      }
    }
    final incomingDeleted = <KdbxUuid?, KdbxDeletedObject>{};

    for (final obj in other.ctx._deletedObjects) {
      if (revived.containsKey(obj.uuid)) {
        continue;
      }
      final ours = deleted[obj.uuid];
      if (ours == null) {
        // Their time, not the time of this merge: it is what a later change
        // to the object is compared with, and stamping it anew would also
        // make it drift on every hop between copies.
        final del = KdbxDeletedObject.create(
          ctx,
          obj.uuid,
          obj.deletionTime.get(),
        );
        ctx._deletedObjects.add(del);
        incomingDeleted[del.uuid] = del;
        deleted[del.uuid] = del;
      } else if (obj.deletionTime.isAfter(ours.deletionTime)) {
        ours.deletionTime.set(obj.deletionTime.get());
      }
    }

    final localObjects = _createObjectIndexWithDuplicates();
    final mergeContext = MergeContext(
      objectIndex: {
        for (final e in localObjects.entries) ...{
          e.key: e.value.first,
        },
      },
      deletedObjects: deleted,
      incomingDeletedObjects: incomingDeleted,
      duplicateObjects: {
        for (final e in localObjects.entries)
          if (e.value.length > 1) ...{
            e.key: e.value.sublist(1),
          },
      },
    );
    for (final e in mergeContext.duplicateObjects.entries) {
      mergeContext.trackWarning(
        'Local file carries ${e.value.length + 1} live objects with the same '
        'uuid ${e.key} - see KdbxDao.mergeDuplicateUuidEntries.',
      );
    }
    for (final e in other._createObjectIndexWithDuplicates().entries) {
      if (e.value.length > 1) {
        mergeContext.trackWarning(
          'Incoming file carries ${e.value.length} live objects with the same '
          'uuid ${e.key} - only the first one will be merged.',
        );
      }
    }

    // sync binaries
    for (final binary in other.ctx.binariesIterable) {
      if (ctx.findBinaryByValue(binary) == null) {
        ctx.addBinary(binary);
        mergeContext.trackChange(
          this,
          debug: 'adding new binary ${binary.value.length}',
        );
      }
    }
    meta.merge(other.meta);
    rootGroup.merge(mergeContext, other.rootGroup);
    _applyDeletions(mergeContext, rootGroup);
    _keepRevived(mergeContext, revived, droppedHere: droppedHere);

    _logger.info('Finished merging:\n${mergeContext.debugChanges()}');
    final incomingObjects = other._createObjectIndex();
    _logger.info(
      'Merged: ${mergeContext.merged} vs. '
      '(local objects: ${mergeContext.objectIndex.length}, '
      'incoming objects: ${incomingObjects.length})',
    );

    // sanity checks
    if (mergeContext.merged.keys.length != mergeContext.objectIndex.length) {
      // TODO figure out what went wrong.
    }
    return mergeContext;
  }

  /// The uuids which either file holds live and recorded as deleted at once,
  /// each with the latest record of it in either file.
  ///
  /// The merge before this release left files that way, see
  /// [MergeDeletionRecordDropped]: such an object has been in the file all
  /// along, so its records are void. Neither file's are taken over or
  /// decide anything - not even one of a file that does not hold the object,
  /// such as a copy that really deleted it and has not merged since: the
  /// object has been in use elsewhere after that, and keeping it loses
  /// nothing. [_keepRevived] stamps the object, so that a copy still holding
  /// one of the records keeps it as well.
  Map<KdbxUuid, KdbxDeletedObject> _liveAndDeleted(KdbxBody other) {
    final revived = <KdbxUuid, KdbxDeletedObject>{};
    for (final body in [this, other]) {
      if (body.ctx._deletedObjects.isEmpty) {
        continue;
      }
      final live = body._createObjectIndex();
      for (final record in body.ctx._deletedObjects) {
        if (live.containsKey(record.uuid)) {
          revived[record.uuid] = record;
        }
      }
    }
    if (revived.isEmpty) {
      return revived;
    }
    for (final record in [
      ...ctx._deletedObjects,
      ...other.ctx._deletedObjects,
    ]) {
      final known = revived[record.uuid];
      if (known != null && record.deletionTime.isAfter(known.deletionTime)) {
        revived[record.uuid] = record;
      }
    }
    return revived;
  }

  /// Keeps what [_liveAndDeleted] found, and reports it. [droppedHere] are
  /// the uuids whose records this file held, which have to reach the disk
  /// gone.
  void _keepRevived(
    MergeContext mergeContext,
    Map<KdbxUuid, KdbxDeletedObject> revived, {
    required Set<KdbxUuid> droppedHere,
  }) {
    if (revived.isEmpty) {
      return;
    }
    final live = _createObjectIndex();
    for (final MapEntry(key: uuid, value: record) in revived.entries) {
      // live in one of the two files, and no record left to remove it: if
      // only the other file had it, it was copied in.
      final object = live[uuid];
      if (object == null) {
        continue;
      }
      // Only needed where the record is newer than the last change: a copy
      // still holding an older one keeps the object anyway.
      final stamp = mergeContext.isDeletedAfterLastChange(record, object);
      if (stamp || droppedHere.contains(uuid)) {
        object.modifyStructural(() {
          if (stamp) {
            object.times.locationChanged.set(
              KdbxTimes.nowAfter(record.deletionTime.get()),
            );
          }
        });
        mergeContext.trackChange(
          object,
          debug: 'kept: was live and deleted at once.',
        );
      }
      mergeContext.trackEvent(
        MergeDeletionRecordDropped(
          object,
          deletionTime: record.deletionTime.get(),
        ),
      );
    }
  }

  /// Decides, children first, which objects of the merged tree under [group]
  /// a deletion record removes. Returns whether [group] itself stays.
  ///
  /// An object with a record stays when the record is not newer than its
  /// last change, its data or its location (see
  /// [MergeContext.isDeletedAfterLastChange]) - and a group also stays when
  /// anything inside it does. That is how an entry created in a group, or
  /// moved into it, after another device deleted the group survives: the
  /// device that deleted it never knew of the entry, so it recorded no
  /// deletion for it, and the group stays to hold it. What the deleting
  /// device did know of in the group has records of its own and goes.
  ///
  /// The record of an object that stays is dropped, so that no file holds a
  /// uuid both live and deleted: a copy that still has the record merges
  /// this file's object back in the same way, by the same comparison.
  ///
  /// Every object is decided from the merged tree, which both copies arrive
  /// at alike, so both decide alike. Also every copy of a uuid that a file
  /// wrongly holds more than once, see [KdbxFile.duplicateUuidsOnOpen].
  bool _applyDeletions(MergeContext mergeContext, KdbxGroup group) {
    var anythingStays = false;
    for (final child in [...group.groups, ...group.entries]) {
      final stays = child is KdbxGroup
          ? _applyDeletions(mergeContext, child)
          : _decideDeletion(mergeContext, child, anythingInsideStays: false);
      if (stays) {
        anythingStays = true;
      }
    }
    if (identical(group, rootGroup)) {
      return true;
    }
    return _decideDeletion(
      mergeContext,
      group,
      anythingInsideStays: anythingStays,
    );
  }

  bool _decideDeletion(
    MergeContext mergeContext,
    KdbxObject object, {
    required bool anythingInsideStays,
  }) {
    final record = mergeContext.deletedObjects[object.uuid];
    if (record == null) {
      return true;
    }
    if (anythingInsideStays ||
        !mergeContext.isDeletedAfterLastChange(record, object)) {
      _keepDespiteRecord(mergeContext, object);
      return true;
    }
    final parent = object.parent!;
    if (object is KdbxGroup) {
      parent.internalRemoveGroup(object);
    } else if (object is KdbxEntry) {
      parent.internalRemoveEntry(object);
    } else {
      throw StateError('Invalid object type $object');
    }
    // The object has left the tree, so it must stop claiming a parent, the
    // way [KdbxDao.deletePermanently] does it. A caller still holding it - an
    // open screen, say - otherwise sees an object which is out of its group's
    // child list but still names that group, which is how
    // `deletePermanently` came to record a second deleted object for the
    // same uuid and only then fail. Unlike `deletePermanently` this does
    // *not* stamp `locationChanged`: nothing is moving anywhere, and since
    // that time decides where an object belongs in a merge, a fresh one on a
    // removed object could only ever mislead.
    object.internalChangeParent(null);
    object.internalMarkRemovedByMerge();
    if (mergeContext.importedObjects.contains(object)) {
      // copied in by this very merge, and gone again: as far as this file
      // is concerned nothing happened, so nothing is reported either.
      mergeContext.internalForgetEventsOf(object);
      return false;
    }
    mergeContext.trackChange(object, debug: 'was deleted.');
    mergeContext.trackEvent(
      MergeObjectDeleted(object, deletionTime: record.deletionTime.get()),
    );
    return false;
  }

  /// Drops the deletion record of [object], which stays.
  void _keepDespiteRecord(MergeContext mergeContext, KdbxObject object) {
    final uuid = object.uuid;
    final record = mergeContext.deletedObjects.remove(uuid);
    if (mergeContext.incomingDeletedObjects.remove(uuid) != null) {
      // a record the other file had and we have not taken over after all:
      // this file does not change, but the user may want to know why the
      // object is still here.
      ctx.removeDeletedObject(uuid);
      // Not for an object copied in by this merge: then the other file held
      // it live and deleted at once, and refused nothing of ours. That is
      // dealt with before, see [_liveAndDeleted] - this only guards a file
      // carrying the uuid twice.
      if (!mergeContext.importedObjects.contains(object)) {
        mergeContext.trackEvent(
          MergeDeletionRefused(
            object,
            deletionTime: record?.deletionTime.get(),
          ),
        );
      }
      return;
    }
    // Every record for the uuid, not just the one the merge decided by: a
    // file can hold more than one, which `deletePermanently` used to write
    // for an object that had already left the tree.
    ctx.removeDeletedObject(uuid);
    // A record leaving the file has to reach the disk. The object is dirty
    // anyway, having just been copied in - one this file held live already
    // left its records before, see [_liveAndDeleted] - but this does not
    // rely on that.
    object.modifyStructural(() {});
    mergeContext.trackChange(
      object,
      debug: 'kept: changed after it was deleted.',
    );
  }

  xml.XmlDocument generateXml(ProtectedSaltGenerator saltGenerator) {
    final rootGroupNode = rootGroup.toXml();
    // update protected values...
    for (final el
        in rootGroupNode
            .findAllElements(KdbxXml.NODE_VALUE)
            .where(
              (el) =>
                  el.getAttribute(KdbxXml.ATTR_PROTECTED)?.toLowerCase() ==
                  'true',
            )) {
      final pv = KdbxFile.protectedValues[el];
      if (pv != null) {
        final newValue = saltGenerator.encryptToBase64(pv.getText());
        el.children.clear();
        el.children.add(xml.XmlText(newValue));
      } else {
        //        assert((() {
        //          _logger.severe('Unable to find protected value for $el ${el.parent.parent} (children: ${el.children})');
        //          return false;
        //        })());
        // this is always an error, not just during debug.
        throw StateError('Unable to find protected value for $el ${el.parent}');
      }
    }

    final builder = xml.XmlBuilder();
    builder.processing(
      'xml',
      'version="1.0" encoding="utf-8" standalone="yes"',
    );
    builder.element(
      'KeePassFile',
      nest: [
        meta.toXml(),
        () => builder.element(
          'Root',
          nest: [
            rootGroupNode,
            XmlUtils.createNode(
              KdbxXml.NODE_DELETED_OBJECTS,
              ctx._deletedObjects.map((e) => e.toXml()).toList(),
            ),
          ],
        ),
      ],
    );
    //    final doc = xml.XmlDocument();
    //    doc.children.add(xml.XmlProcessing(
    //        'xml', 'version="1.0" encoding="utf-8" standalone="yes"'));
    final node = builder.buildDocument();

    return node;
  }
}

abstract class OverwriteContext {
  const OverwriteContext();
  static const noop = OverwriteContextNoop();
  void trackChange(KdbxObject object, {String? node, String? debug});
}

class OverwriteContextNoop implements OverwriteContext {
  const OverwriteContextNoop();
  @override
  void trackChange(KdbxObject object, {String? node, String? debug}) {}
}

class MergeChange {
  MergeChange({this.object, this.node, this.debug});

  final KdbxNode? object;

  /// the name of the subnode of [object].
  final String? node;
  final String? debug;

  String debugString() {
    return [node, debug].where((e) => e != null).join(' ');
  }
}

class MergeWarning {
  MergeWarning(this.debug);

  final String debug;

  @override
  String toString() {
    return debug;
  }
}

class MergeContext implements OverwriteContext {
  MergeContext({
    required this.objectIndex,
    required this.deletedObjects,
    this.incomingDeletedObjects = const {},
    this.duplicateObjects = const {},
  });

  /// One object per uuid - the first one, if the file carries duplicates.
  final Map<KdbxUuid, KdbxObject> objectIndex;

  /// Every deletion record the file holds after the merge, by uuid - the
  /// ones it already had as well as [incomingDeletedObjects].
  final Map<KdbxUuid?, KdbxDeletedObject> deletedObjects;

  /// The deletion records this merge took over from the other file, by uuid:
  /// the subset of [deletedObjects] that is new.
  final Map<KdbxUuid?, KdbxDeletedObject> incomingDeletedObjects;

  /// The live objects which [objectIndex] could not represent, because another
  /// live object already carries the same uuid. Empty for a healthy file, see
  /// [KdbxFile.duplicateUuidsOnOpen].
  final Map<KdbxUuid, List<KdbxObject>> duplicateObjects;
  final Map<KdbxUuid, KdbxObject> merged = {};

  /// The objects this merge copied in from the other file.
  @internal
  final Set<KdbxObject> importedObjects = Set.identity();

  /// Whether [record] says [object] was deleted after it last changed - its
  /// data or where it is. Only then does the deletion win.
  ///
  /// A move counts as a change: it is a decision about the object made after
  /// the deletion, and it is how an entry is taken back out of the recycle
  /// bin. KeePassXC compares the modification time alone. A deletion in the
  /// same second as the last change does not win, since times are kept to
  /// the second and the change may well have come later.
  @internal
  bool isDeletedAfterLastChange(KdbxDeletedObject record, KdbxObject object) =>
      record.deletionTime.isAfter(object.times.lastModificationTime) &&
      record.deletionTime.isAfter(object.times.locationChanged);

  /// Whether [incoming], an object only the other file has, would only be
  /// removed again once the trees are merged, so is better not copied in.
  ///
  /// Exactly when `KdbxBody._applyDeletions` would remove it: its record is
  /// newer than its last change, and - for a group - nothing would end up
  /// inside it that stays. Something this file also has stays where it is
  /// here unless the other file moved it into the group later, see
  /// `KdbxGroup._mergeSubObjects`: a group the other file would move
  /// something into is copied in, and the verdict afterwards decides. One
  /// that only still holds what we moved out of it before deleting it is
  /// not - but what it holds is still merged, by
  /// `KdbxGroup._mergeLeftBehind`.
  @internal
  bool wouldOnlyBeRemoved(KdbxObject incoming) {
    final record = deletedObjects[incoming.uuid];
    if (record == null || !isDeletedAfterLastChange(record, incoming)) {
      return false;
    }
    if (incoming is KdbxGroup) {
      for (final child in [...incoming.groups, ...incoming.entries]) {
        final local = objectIndex[child.uuid];
        if (local != null) {
          if (child.wasMovedAfter(local)) {
            return false;
          }
        } else if (!wouldOnlyBeRemoved(child)) {
          return false;
        }
      }
    }
    return true;
  }

  /// Takes back the events of [object], which this merge copied in and then
  /// removed again.
  @internal
  void internalForgetEventsOf(KdbxObject object) =>
      _events.removeWhere((event) => identical(event.object, object));

  final List<MergeChange> changes = [];
  final List<MergeWarning> warnings = [];

  /// What this merge did, object by object, in terms a user can be told
  /// about - see [MergeEvent]. Empty when the merge changed nothing a user
  /// would recognise.
  late final List<MergeEvent> events = UnmodifiableListView(_events);
  final List<MergeEvent> _events = [];

  /// How much this merge changed: every tracked change, plus every deletion
  /// record it took over from the other file. Zero exactly when the merge
  /// changed no entry, group, attachment or deletion record. Changes to the
  /// database's own settings ([KdbxMeta]) are not tracked, and so not
  /// counted, yet. Nor is a group whose other copy carries a newer
  /// modification time but no field that differs: it takes over that time
  /// without a tracked change, and without becoming dirty.
  ///
  /// Not the same signal as [KdbxFile.isDirty]: a deletion record for an
  /// object this file never had is counted here, but does not make the file
  /// dirty, so a caller that saves only when the file is dirty does not
  /// persist it.
  ///
  /// An object the merge removed because of a record it took over counts
  /// twice, once for the record and once for the removal; this is a measure
  /// of the work done, not a count of objects.
  ///
  /// It used to count [deletedObjects] - every record in the file, including
  /// those both copies had long agreed on - so a file with any deletion in
  /// its past never reported a merge as a no-op.
  int totalChanges() {
    return incomingDeletedObjects.length + changes.length;
  }

  void markAsMerged(KdbxObject object) {
    if (merged.containsKey(object.uuid)) {
      throw StateError(
        'object was already market as merged! ${object.uuid}: $object',
      );
    }
    merged[object.uuid] = object;
  }

  @override
  void trackChange(KdbxNode? object, {String? node, String? debug}) {
    changes.add(
      MergeChange(
        object: object,
        node: node,
        debug: debug,
      ),
    );
  }

  void trackWarning(String warning) {
    _logger.warning(warning, StackTrace.current);
    warnings.add(MergeWarning(warning));
  }

  void trackEvent(MergeEvent event) {
    _events.add(event);
  }

  String debugChanges() {
    final group = changes.groupBy(
      (element) => element.object,
      valueTransform: (x) => x,
    );
    return group.entries
        .map(
          (e) => [
            e.key.toString(),
            ...e.value.map((e) => e.debugString()),
          ].join('\n    '),
        )
        .join('\n');
  }

  String debugSummary() {
    return 'Changes: ${changes.length}, '
        'Deleted: ${incomingDeletedObjects.length}, '
        'Warnings: ${warnings.isEmpty ? 'None' : warnings.join(', ')}';
  }

  @override
  String toString() {
    return '$runtimeType{${debugSummary()}}';
  }
}

class _KeysV4 {
  _KeysV4(this.hmacKey, this.cipherKey, this.transformedKey);

  final Uint8List hmacKey;
  final Uint8List cipherKey;

  /// The KDF output the other two keys were built from. Retained so it can be
  /// handed out as [KdbxFile.transformedKeyCredentials].
  final Uint8List transformedKey;
}

class KdbxFormat {
  KdbxFormat([Argon2? argon2])
    : assert(kdbxKeyCommonAssertConsistency()),
      argon2 = argon2 == null || !argon2.isImplemented
          ? const PointyCastleArgon2()
          : argon2;

  final Argon2 argon2;
  static bool dartWebWorkaround = false;

  /// Creates a new, empty [KdbxFile] with default settings.
  /// If [header] is not given by default a kdbx 4.0 file will be created.
  KdbxFile create(
    Credentials credentials,
    String name, {
    String? generator,
    KdbxHeader? header,
  }) {
    header ??= KdbxHeader.createV4();
    final ctx = KdbxReadWriteContext(binaries: [], header: header);
    final meta = KdbxMeta.create(
      databaseName: name,
      ctx: ctx,
      generator: generator,
    );
    final rootGroup = KdbxGroup.create(ctx: ctx, parent: null, name: name);
    final body = KdbxBody.create(meta, rootGroup);
    return KdbxFile(
      ctx,
      this,
      credentials,
      header,
      body,
    );
  }

  Future<KdbxFile> read(Uint8List input, Credentials credentials) async {
    final reader = ReaderHelper(input);
    final header = KdbxHeader.read(reader);
    if (header.version.major == KdbxVersion.V3.major) {
      return await _loadV3(header, reader, credentials);
    } else if (header.version.major == KdbxVersion.V4.major) {
      return await _loadV4(header, reader, credentials);
    } else {
      _logger.finer('Unsupported version for $header');
      throw KdbxUnsupportedException(
        'Unsupported kdbx version '
        '${header.version}.'
        ' Only 3.x and 4.x is supported.',
      );
    }
  }

  /// Saves the given file.
  Future<T> save<T>(KdbxFile file, FileSaveCallback<T> saveBytes) async {
    _logger.finer(
      'Saving ${file.body.rootGroup.uuid} '
      '(locked: ${file.saveLock.locked})',
    );
    if (file.credentials is TransformedKeyCredentials) {
      // saving rotates the kdf salt, and a derived key cannot be re-derived for
      // the new salt without the original credentials.
      throw KdbxUnsupportedException(
        'Files opened with TransformedKeyCredentials are read-only. '
        'Reopen with the original credentials to save.',
      );
    }
    return file.saveLock.synchronized(() async {
      final savedAt = TimeSequence.now();
      final bytes = await _saveSynchronized(file);

      _logger.fine('Saving bytes.');
      final ret = await saveBytes(bytes);
      _logger.fine('Saved bytes.');

      file.onSaved(savedAt);
      return ret;
    });
  }

  Future<Uint8List> _saveSynchronized(KdbxFile file) async {
    final body = file.body;
    final header = file.header;

    // Before anything is serialized, because binary ids are positions in the
    // pool and [KdbxBody.generateXml] resolves them as it goes.
    //
    // Nothing else ever shrinks the pool: detaching an attachment leaves it
    // for the revisions that still hold it, and when those go there is no
    // second pass. A database could only grow, which is how an AuthPass file
    // got large enough for another client to refuse it
    // (authpass/authpass#427). KeePass and KeePassXC both rebuild the pool
    // from references on write; this is the same thing.
    final collected = file.ctx.removeUnreferencedBinaries(
      body.referencedBinaries(),
    );
    if (collected.isNotEmpty) {
      final bytes = collected.fold<int>(
        0,
        (sum, binary) => sum + binary.value.length,
      );
      _logger.info(
        'Dropping ${collected.length} unreferenced binaries ($bytes bytes).',
      );
    }

    final output = BytesBuilder();
    final writer = WriterHelper(output);
    header.generateSalts();
    header.write(writer);
    final headerHash =
        (crypto.sha256.convert(writer.output.toBytes()).bytes as Uint8List);

    if (file.header.version < KdbxVersion.V3) {
      throw UnsupportedError('Unsupported version ${header.version}');
    } else if (file.header.version < KdbxVersion.V4) {
      final streamKey =
          file.header.fields[HeaderFields.ProtectedStreamKey]!.bytes;
      final gen = ProtectedSaltGenerator(streamKey);

      body.meta.headerHash.set(headerHash.buffer);
      await body.writeV3(writer, file, gen);
    } else if (header.version.major == KdbxVersion.V4.major) {
      final headerBytes = writer.output.toBytes();
      writer.writeBytes(headerHash);
      final gen = _createProtectedSaltGenerator(header);
      final keys = await _computeKeysV4(header, file.credentials);
      final headerHmac = _getHeaderHmac(headerBytes, keys.hmacKey);
      writer.writeBytes(headerHmac.bytes as Uint8List);
      body.writeV4(writer, file, gen, keys);
      // salts were rotated above, so the derived key is a new one.
      file.setTransformedKey(keys.transformedKey);
    } else {
      throw UnsupportedError('Unsupported version ${header.version}');
    }
    return output.toBytes();
  }

  Future<KdbxFile> _loadV3(
    KdbxHeader header,
    ReaderHelper reader,
    Credentials credentials,
  ) async {
    //    _getMasterKeyV3(header, credentials);
    final masterKey = await _generateMasterKeyV3(header, credentials);
    final encryptedPayload = reader.readRemaining();
    final content = _decryptContent(header, masterKey, encryptedPayload);
    final blocks = HashedBlockReader.readBlocks(ReaderHelper(content));

    _logger.finer('compression: ${header.compression}');
    final ctx = KdbxReadWriteContext(binaries: [], header: header);
    if (header.compression == Compression.gzip) {
      final xml = KdbxFormat._gzipDecode(blocks);
      final string = utf8.decode(xml);
      return KdbxFile(
        ctx,
        this,
        credentials,
        header,
        _loadXml(ctx, header, string),
      );
    } else {
      return KdbxFile(
        ctx,
        this,
        credentials,
        header,
        _loadXml(ctx, header, utf8.decode(blocks)),
      );
    }
  }

  Future<KdbxFile> _loadV4(
    KdbxHeader header,
    ReaderHelper reader,
    Credentials credentials,
  ) async {
    final headerBytes = reader.byteData.sublist(0, header.endPos);
    final hash = crypto.sha256.convert(headerBytes).bytes;
    final actualHash = reader.readBytes(hash.length);
    if (!ByteUtils.eq(hash, actualHash)) {
      _logger.fine(
        'Does not match ${ByteUtils.toHexList(hash)} '
        'vs ${ByteUtils.toHexList(actualHash)}',
      );
      throw KdbxCorruptedFileException('Header hash does not match.');
    }
    //    _logger
    //        .finest('KdfParameters: ${header.readKdfParameters.toDebugString()}');
    _logger.finest('Header hash matches.');
    final keys = await _computeKeysV4(header, credentials);
    final headerHmac = _getHeaderHmac(
      reader.byteData.sublist(0, header.endPos),
      keys.hmacKey,
    );
    final expectedHmac = reader.readBytes(headerHmac.bytes.length);
    //    _logger.fine('Expected: ${ByteUtils.toHexList(expectedHmac)}');
    //    _logger.fine('Actual  : ${ByteUtils.toHexList(headerHmac.bytes)}');
    if (!ByteUtils.eq(headerHmac.bytes, expectedHmac)) {
      throw KdbxInvalidKeyException();
    }
    //    final hmacTransformer = crypto.Hmac(crypto.sha256, hmacKey.bytes);
    //    final blockreader.readBytes(32);
    final bodyContent = hmacBlockTransformer(keys.hmacKey, reader);
    final decrypted = decrypt(header, bodyContent, keys.cipherKey);
    _logger.finer('compression: ${header.compression}');
    if (header.compression == Compression.gzip) {
      final content = KdbxFormat._gzipDecode(decrypted);
      final contentReader = ReaderHelper(content);
      final innerHeader = KdbxHeader.readInnerHeaderFields(
        contentReader,
        header.version,
      );

      //      _logger.fine('inner header fields: $headerFields');
      //      header.innerFields.addAll(headerFields);
      header.innerHeader.updateFrom(innerHeader);
      final xml = utf8.decode(contentReader.readRemaining());
      final context = KdbxReadWriteContext(binaries: [], header: header);
      return KdbxFile(
        context,
        this,
        credentials,
        header,
        _loadXml(context, header, xml),
      )..setTransformedKey(keys.transformedKey);
    }
    throw StateError('Kdbx4 without compression is not yet supported.');
  }

  Uint8List hmacBlockTransformerEncrypt(Uint8List hmacKey, Uint8List data) {
    final writer = WriterHelper();
    final reader = ReaderHelper(data);
    const blockSize = 1024 * 1024;
    var blockIndex = 0;
    while (true) {
      final blockData = reader.readBytesUpTo(blockSize);
      final calculatedHash = _hmacHashForBlock(hmacKey, blockIndex, blockData);
      writer.writeBytes(calculatedHash);
      writer.writeUint32(blockData.length);
      if (blockData.isEmpty) {
        //        writer.writeUint32(0);
        return writer.output.toBytes();
      }
      writer.writeBytes(blockData);
      blockIndex++;
    }
  }

  Uint8List _hmacKeyForBlockIndex(Uint8List hmacKey, int blockIndex) {
    final blockKeySrc = WriterHelper()
      ..writeUint64(blockIndex)
      ..writeBytes(hmacKey);
    return crypto.sha512.convert(blockKeySrc.output.toBytes()).bytes
        as Uint8List;
  }

  Uint8List _hmacHashForBlock(
    Uint8List hmacKey,
    int blockIndex,
    Uint8List blockData,
  ) {
    final blockKey = _hmacKeyForBlockIndex(hmacKey, blockIndex);
    final tmp = WriterHelper();
    tmp.writeUint64(blockIndex);
    tmp.writeInt32(blockData.length);
    tmp.writeBytes(blockData);
    //      _logger.fine('blockHash: ${ByteUtils.toHexList(tmp.output.toBytes())}');
    //      _logger.fine('blockKey: ${ByteUtils.toHexList(blockKey.bytes)}');
    final hmac = crypto.Hmac(crypto.sha256, blockKey);
    final calculatedHash = hmac.convert(tmp.output.toBytes());
    return calculatedHash.bytes as Uint8List;
  }

  Uint8List hmacBlockTransformer(Uint8List hmacKey, ReaderHelper reader) {
    final ret = <int>[];
    var blockIndex = 0;
    while (true) {
      final blockHash = reader.readBytes(32);
      final blockLength = reader.readUint32();
      final blockBytes = reader.readBytes(blockLength);
      final calculatedHash = _hmacHashForBlock(hmacKey, blockIndex, blockBytes);
      //      _logger
      //          .fine('CalculatedHash: ${ByteUtils.toHexList(calculatedHash.bytes)}');
      if (!ByteUtils.eq(blockHash, calculatedHash)) {
        throw KdbxCorruptedFileException('Invalid hash block.');
      }

      if (blockLength < 1) {
        return Uint8List.fromList(ret);
      }
      blockIndex++;
      ret.addAll(blockBytes);
    }
  }

  Uint8List decrypt(
    KdbxHeader header,
    Uint8List encrypted,
    Uint8List cipherKey,
  ) {
    final cipher = header.cipher;
    if (cipher == Cipher.aes) {
      _logger.fine('We need AES');
      final result = _decryptContentV4(header, cipherKey, encrypted);
      return result;
    } else if (cipher == Cipher.chaCha20) {
      _logger.fine('We need chacha20');
      //      throw UnsupportedError('chacha20 not yet supported $cipherId');
      return transformContentV4ChaCha20(header, encrypted, cipherKey);
    } else {
      throw UnsupportedError('Unsupported cipherId $cipher');
    }
  }

  Uint8List transformContentV4ChaCha20(
    KdbxHeader header,
    Uint8List encrypted,
    Uint8List cipherKey,
  ) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV]!.bytes;
    final chaCha = ChaCha7539Engine()
      ..init(true, ParametersWithIV(KeyParameter(cipherKey), encryptionIv));
    return chaCha.process(encrypted);
    // return cryptography.chacha20.decrypt(encrypted, key, nonce: nonce);
  }

  //  Uint8List _transformDataV4Aes() {
  //  }

  crypto.Digest _getHeaderHmac(Uint8List headerBytes, Uint8List key) {
    final writer = WriterHelper()
      ..writeUint32(0xffffffff)
      ..writeUint32(0xffffffff)
      ..writeBytes(key);
    final hmacKey = crypto.sha512.convert(writer.output.toBytes()).bytes;
    final src = headerBytes;
    final hmacKeyStuff = crypto.Hmac(crypto.sha256, hmacKey);
    return hmacKeyStuff.convert(src);
  }

  Future<_KeysV4> _computeKeysV4(
    KdbxHeader header,
    Credentials credentials,
  ) async {
    final masterSeed = header.fields[HeaderFields.MasterSeed]!.bytes;
    final kdfParameters = header.readKdfParameters;
    if (masterSeed.length != 32) {
      throw const FormatException('Master seed must be 32 bytes.');
    }

    final key = await _transformKeyV4(header, kdfParameters, credentials);

    //    final keyWithSeed = Uint8List(65);
    //    keyWithSeed.replaceRange(0, masterSeed.length, masterSeed);
    //    keyWithSeed.replaceRange(
    //        masterSeed.length, masterSeed.length + key.length, key);
    //    keyWithSeed[64] = 1;
    final keyWithSeed = masterSeed + key + Uint8List.fromList([1]);
    assert(keyWithSeed.length == 65);
    final cipher = crypto.sha256.convert(keyWithSeed.sublist(0, 64));
    final hmacKey = crypto.sha512.convert(keyWithSeed);

    return _KeysV4(hmacKey.bytes as Uint8List, cipher.bytes as Uint8List, key);
  }

  /// Runs the key derivation function over [credentials], or skips it when the
  /// caller already supplied the derived key via [TransformedKeyCredentials].
  Future<Uint8List> _transformKeyV4(
    KdbxHeader header,
    VarDictionary kdfParameters,
    Credentials credentials,
  ) async {
    if (credentials is TransformedKeyCredentials) {
      final actual = header.kdfFingerprint;
      if (credentials.kdfFingerprint != actual) {
        throw KdbxTransformedKeyStaleException(
          expected: credentials.kdfFingerprint,
          actual: actual,
        );
      }
      return credentials.transformedKey;
    }
    return await KeyEncrypterKdf(
      argon2,
    ).encrypt(credentials.getHash(), kdfParameters);
  }

  ProtectedSaltGenerator _createProtectedSaltGenerator(KdbxHeader header) {
    final protectedValueEncryption = header.innerRandomStreamEncryption;
    final streamKey = header.protectedStreamKey;
    if (protectedValueEncryption == ProtectedValueEncryption.salsa20) {
      return ProtectedSaltGenerator(streamKey!);
    } else if (protectedValueEncryption == ProtectedValueEncryption.chaCha20) {
      return ProtectedSaltGenerator.chacha20(streamKey!);
    } else {
      throw KdbxUnsupportedException(
        'Inner encryption: $protectedValueEncryption',
      );
    }
  }

  KdbxBody _loadXml(
    KdbxReadWriteContext ctx,
    KdbxHeader header,
    String xmlString,
  ) {
    final gen = _createProtectedSaltGenerator(header);

    final document = xml.XmlDocument.parse(xmlString);
    KdbxReadWriteContext.setKdbxContextForNode(document, ctx);

    for (final el
        in document
            .findAllElements(KdbxXml.NODE_VALUE)
            .where((el) => el.getAttributeBool(KdbxXml.ATTR_PROTECTED))) {
      try {
        final pw = gen.decryptBase64(el.text.trim());
        if (pw == null) {
          continue;
        }
        KdbxFile.protectedValues[el] = ProtectedValue.fromString(pw);
      } catch (e, stackTrace) {
        final stringKey = el.parentElement!
            .singleElement(KdbxXml.NODE_KEY)
            ?.text;
        final uuid = el.parentElement?.parentElement
            ?.singleElement(KdbxXml.NODE_UUID)
            ?.text;
        _logger.severe(
          'Error while decoding protected value in '
          '{${el.breadcrumbsNames()}} of key'
          ' {$stringKey} of entry {$uuid}.',
          e,
          stackTrace,
        );

        rethrow;
      }
    }

    final keePassFile = document.findElements('KeePassFile').single;
    final meta = keePassFile.findElements('Meta').single;
    final root = keePassFile.findElements('Root').single;

    final kdbxMeta = KdbxMeta.read(meta, ctx);
    // kdbx < 4 has binaries in the meta section, >= 4 in the binary header.
    final binaries = kdbxMeta.binaries?.isNotEmpty == true
        ? kdbxMeta.binaries!
        : header.innerHeader.binaries.map(
            (e) => KdbxBinary.readBinaryInnerHeader(e),
          );

    final deletedObjects =
        root
            .findElements(KdbxXml.NODE_DELETED_OBJECTS)
            .singleOrNull
            ?.let(
              (el) => el
                  .findElements(KdbxDeletedObject.NODE_NAME)
                  .map((node) => KdbxDeletedObject.read(node, ctx)),
            ) ??
        [];
    ctx.initContext(binaries, deletedObjects);

    final rootGroup = KdbxGroup.read(
      ctx,
      null,
      root.findElements(KdbxXml.NODE_GROUP).single,
    );
    _logger.fine('successfully read Meta.');
    return KdbxBody.read(keePassFile, kdbxMeta, rootGroup);
  }

  Uint8List _decryptContent(
    KdbxHeader header,
    Uint8List masterKey,
    Uint8List encryptedPayload,
  ) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV]!.bytes;
    final decryptCipher = CBCBlockCipher(AESEngine());
    decryptCipher.init(
      false,
      ParametersWithIV(KeyParameter(masterKey), encryptionIv),
    );
    _logger.finer(
      'decrypting ${encryptedPayload.length} with block size '
      '${decryptCipher.blockSize}',
    );
    final paddedDecrypted = AesHelper.processBlocks(
      decryptCipher,
      encryptedPayload,
    );

    final streamStart = header.fields[HeaderFields.StreamStartBytes]!.bytes;

    if (paddedDecrypted.lengthInBytes < streamStart.lengthInBytes) {
      _logger.warning(
        'decrypted content was shorter than expected stream start block.',
      );
      throw KdbxInvalidKeyException();
    }

    if (!ByteUtils.eq(
      streamStart,
      paddedDecrypted.sublist(0, streamStart.lengthInBytes),
    )) {
      throw KdbxInvalidKeyException();
    }

    final decrypted = AesHelper.unpad(paddedDecrypted);

    // ignore: unnecessary_cast
    final content = decrypted.sublist(streamStart.lengthInBytes) as Uint8List;
    return content;
  }

  Uint8List _decryptContentV4(
    KdbxHeader header,
    Uint8List cipherKey,
    Uint8List encryptedPayload,
  ) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV]!.bytes;

    final decryptCipher = CBCBlockCipher(AESEngine());
    decryptCipher.init(
      false,
      ParametersWithIV(KeyParameter(cipherKey), encryptionIv),
    );
    final paddedDecrypted = AesHelper.processBlocks(
      decryptCipher,
      encryptedPayload,
    );

    final decrypted = AesHelper.unpad(paddedDecrypted);
    return decrypted;
  }

  /// TODO combine this with [_decryptContentV4] (or [_encryptDataAes]?)
  Uint8List _encryptContentV4Aes(
    KdbxHeader header,
    Uint8List cipherKey,
    Uint8List bytes,
  ) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV]!.bytes;
    final encryptCypher = CBCBlockCipher(AESEngine());
    encryptCypher.init(
      true,
      ParametersWithIV(KeyParameter(cipherKey), encryptionIv),
    );
    final paddedBytes = AesHelper.pad(bytes, encryptCypher.blockSize);
    return AesHelper.processBlocks(encryptCypher, paddedBytes);
  }

  static Future<Uint8List> _generateMasterKeyV3(
    KdbxHeader header,
    Credentials credentials,
  ) async {
    final rounds = header.v3KdfTransformRounds;
    final seed = header.fields[HeaderFields.TransformSeed]!.bytes;
    final masterSeed = header.fields[HeaderFields.MasterSeed]!.bytes;
    _logger.finer(
      'Rounds: $rounds (${ByteUtils.toHexList(header.fields[HeaderFields.TransformRounds]!.bytes)})',
    );
    final transformedKey = await KeyEncrypterKdf.encryptAesAsync(
      EncryptAesArgs(seed, credentials.getHash(), rounds),
    );

    final masterKey =
        crypto.sha256
                .convert(Uint8List.fromList(masterSeed + transformedKey))
                .bytes
            as Uint8List;
    return masterKey;
  }

  static Uint8List _encryptDataAes(
    Uint8List masterKey,
    Uint8List payload,
    Uint8List encryptionIv,
  ) {
    final encryptCipher = CBCBlockCipher(AESEngine());
    encryptCipher.init(
      true,
      ParametersWithIV(KeyParameter(masterKey), encryptionIv),
    );
    return AesHelper.processBlocks(
      encryptCipher,
      AesHelper.pad(payload, encryptCipher.blockSize),
    );
  }

  static Uint8List? _gzipEncode(Uint8List bytes) {
    if (dartWebWorkaround) {
      return GZipEncoder().encode(bytes) as Uint8List?;
    }
    return GZipCodec().encode(bytes) as Uint8List;
  }

  static Uint8List _gzipDecode(Uint8List bytes) {
    if (dartWebWorkaround) {
      return GZipDecoder().decodeBytes(bytes);
    }
    return GZipCodec().decode(bytes) as Uint8List;
  }
}
