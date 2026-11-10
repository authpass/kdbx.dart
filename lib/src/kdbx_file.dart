import 'dart:async';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:kdbx/src/credentials/credentials.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:kdbx/src/kdbx_dao.dart';
import 'package:kdbx/src/kdbx_exceptions.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/utils/sequence.dart';
import 'package:logging/logging.dart';
import 'package:quiver/check.dart';
import 'package:synchronized/synchronized.dart';
import 'package:xml/xml.dart' as xml;

final _logger = Logger('kdbx_file');

typedef FileSaveCallback<T> = Future<T> Function(Uint8List bytes);

class KdbxFile {
  KdbxFile(
    this.ctx,
    this.kdbxFormat,
    this._credentials,
    this.header,
    this.body,
  ) {
    for (final obj in _allObjects) {
      obj.file = this;
    }
    final duplicates = findDuplicateUuidObjects();
    duplicateUuidsOnOpen = Set.unmodifiable(duplicates.keys);
    if (duplicates.isNotEmpty) {
      _logger.severe(
        'This file carries ${duplicates.length} uuid(s) which are used by '
        'more than one live object - the residue of a merge bug in kdbx up '
        'to 2.5.0. Merging it will not work correctly until it is repaired, '
        'see KdbxDao.mergeDuplicateUuidEntries. '
        '${duplicates.entries.map((e) => '${e.key}: ${e.value.length}').join(', ')}',
      );
    }
  }

  /// The uuids which were carried by more than one live object when this file
  /// was opened - the residue of the merge bug fixed after 2.5.0, which added
  /// an incoming entry's history revisions to the group as live entries.
  ///
  /// Empty for a healthy file. Reading such a file deliberately succeeds (the
  /// data is all there, and the user needs it), but callers should warn and
  /// offer to repair, see [KdbxDao.mergeDuplicateUuidEntries]. The set is a
  /// snapshot: it keeps saying what the file looked like on disk even after a
  /// repair. For the current state use [findDuplicateUuidObjects].
  late final Set<KdbxUuid> duplicateUuidsOnOpen;

  static final protectedValues = Expando<ProtectedValue>();

  static ProtectedValue? protectedValueForNode(xml.XmlElement node) {
    return protectedValues[node];
  }

  static void setProtectedValueForNode(
    xml.XmlElement node,
    ProtectedValue? value,
  ) {
    protectedValues[node] = value;
  }

  final KdbxFormat kdbxFormat;
  final KdbxReadWriteContext ctx;
  Credentials get credentials => _credentials;
  set credentials(Credentials credentials) {
    // the derived key belongs to the old credentials.
    _transformedKey = null;
    body.meta.modify(() => _credentials = credentials);
  }

  Credentials _credentials;

  Uint8List? _transformedKey;

  /// Records the key derivation output for [transformedKeyCredentials].
  /// Called by [KdbxFormat] after reading or writing a kdbx4 file.
  void setTransformedKey(Uint8List transformedKey) {
    _transformedKey = transformedKey;
  }

  /// Fingerprint of the key derivation parameters currently in the header.
  ///
  /// Changes on every save. Compare against
  /// [TransformedKeyCredentials.kdfFingerprint] to tell whether a stored
  /// derived key still applies to this file.
  String get kdfFingerprint => header.kdfFingerprint;

  /// Credentials which reopen this file without re-running the key derivation
  /// function, or `null` if the file has not been read or written yet in this
  /// session (or is not kdbx4).
  ///
  /// Intended for environments that cannot afford Argon2 — notably the iOS
  /// AutoFill extension, whose process memory limit is far below what Argon2
  /// needs at usual KeePass settings.
  ///
  /// Security: this is as good as the master password *for the current
  /// revision of the file*. It expires on the next save, since
  /// [KdbxHeader.generateSalts] rotates the KDF salt — which bounds the damage
  /// a leaked copy can do, unlike the composite hash. Store it accordingly.
  TransformedKeyCredentials? get transformedKeyCredentials {
    final transformedKey = _transformedKey;
    if (transformedKey == null) {
      return null;
    }
    return TransformedKeyCredentials(
      transformedKey: transformedKey,
      kdfFingerprint: kdfFingerprint,
    );
  }

  final KdbxHeader header;
  final KdbxBody body;
  final Set<KdbxObject> dirtyObjects = {};
  bool get isDirty => dirtyObjects.isNotEmpty;
  final StreamController<Set<KdbxObject>> _dirtyObjectsChanged =
      StreamController<Set<KdbxObject>>.broadcast();

  /// lock used by [KdbxFormat] to synchronize saves,
  /// because save actions are not thread save.
  /// see [KdbxFileInternal.saveLock].
  final Lock _saveLock = Lock();

  Stream<Set<KdbxObject>> get dirtyObjectsChanged =>
      _dirtyObjectsChanged.stream;

  // ignore: prefer_function_declarations_over_variables
  static final FileSaveCallback<Uint8List> _saveToBytes = (bytes) async {
    return bytes;
  };

  // @Deprecated('Use [saveTo] instead.')
  Future<Uint8List> save() async {
    return kdbxFormat.save(this, _saveToBytes);
  }

  Future<T> saveTo<T>(FileSaveCallback<T> saveBytes) {
    return kdbxFormat.save(this, saveBytes);
  }

  /// Marks all dirty objects as clean. Called by [KdbxFormat.save].
  void onSaved(TimeSequence savedAt) {
    final cleanedObjects = dirtyObjects.where((e) => e.clean(savedAt)).toList();

    dirtyObjects.removeAll(cleanedObjects);
    _logger.finer('Saved. Remaining dirty objects: ${dirtyObjects.length}');
    _dirtyObjectsChanged.add(dirtyObjects);
  }

  Iterable<KdbxObject> get _allObjects => body.rootGroup
      .getAllGroups()
      .cast<KdbxObject>()
      .followedBy(body.rootGroup.getAllEntries());

  /// Live objects which share their uuid with at least one other live object,
  /// keyed by that uuid. Every value holds at least two objects. Empty for a
  /// healthy file.
  ///
  /// History entries share their parent entry's uuid by design and are not
  /// live objects, so they never show up here.
  ///
  /// Objects without a usable uuid are skipped rather than grouped together:
  /// [KdbxObject.uuid] throws where the `<UUID>` element is missing or
  /// doubled, and an empty or NIL uuid is not an identity - collapsing
  /// everything that shares one would merge unrelated entries. This runs on
  /// every read, so it must not be the thing that stops a file from opening.
  Map<KdbxUuid, List<KdbxObject>> findDuplicateUuidObjects() {
    final byUuid = <KdbxUuid, List<KdbxObject>>{};
    for (final obj in _allObjects) {
      final uuid = obj.uuidOrNull;
      if (uuid == null || uuid.uuid.isEmpty || uuid.isNil) {
        continue;
      }
      (byUuid[uuid] ??= []).add(obj);
    }
    byUuid.removeWhere((uuid, objects) => objects.length < 2);
    return byUuid;
  }

  void dirtyObject(KdbxObject kdbxObject) {
    dirtyObjects.add(kdbxObject);
    _dirtyObjectsChanged.add(UnmodifiableSetView(Set.of(dirtyObjects)));
  }

  void dispose() {
    _dirtyObjectsChanged.close();
  }

  CachedValue<KdbxGroup>? _recycleBin;

  /// Returns the recycle bin, if it exists, null otherwise.
  KdbxGroup? get recycleBin => (_recycleBin ??= _findRecycleBin()).value;

  CachedValue<KdbxGroup> _findRecycleBin() {
    final uuid = body.meta.recycleBinUUID.get();
    if (uuid?.isNil != false) {
      return CachedValue.withNull();
    }
    try {
      return CachedValue.withValue(findGroupByUuid(uuid));
    } catch (e, stackTrace) {
      _logger.warning(() {
        final groupDebug = body.rootGroup
            .getAllGroups()
            .map((g) => '${g.uuid}: ${g.name}')
            .join('\n');
        return 'All Groups: $groupDebug';
      });
      _logger.severe(
        'Inconsistency error, uuid $uuid not found in groups.',
        e,
        stackTrace,
      );
      return CachedValue.withNull();
    }
  }

  KdbxGroup _createRecycleBin() {
    body.meta.recycleBinEnabled.set(true);
    final group = createGroup(parent: body.rootGroup, name: 'Trash');
    group.icon.set(KdbxIcon.TrashBin);
    group.enableAutoType.set(false);
    group.enableSearching.set(false);
    body.meta.recycleBinUUID.set(group.uuid);
    _recycleBin = CachedValue.withValue(group);
    return group;
  }

  KdbxGroup getRecycleBinOrCreate() {
    return recycleBin ?? _createRecycleBin();
  }

  /// Upgrade v3 file to v4.
  void upgrade(int majorVersion) {
    checkArgument(majorVersion == 4, message: 'Must be majorVersion 4');
    body.meta.settingsChanged.setToNow();
    body.meta.headerHash.remove();
    header.upgrade(majorVersion);
  }

  /// Merges the given file into this file.
  /// Both files must have the same origin (ie. same root group UUID).
  /// FIXME: THiS iS NOT YET FINISHED, DO NOT USE.
  MergeContext merge(KdbxFile other) {
    if (other.body.rootGroup.uuid != body.rootGroup.uuid) {
      throw KdbxUnsupportedException(
        'Root groups of source and dest file do not match.',
      );
    }
    return body.merge(other.body);
  }
}

extension KdbxInternal on KdbxFile {
  Lock get saveLock => _saveLock;
}

class CachedValue<T> {
  CachedValue.withNull() : value = null;
  CachedValue.withValue(this.value) : assert(value != null);

  final T? value;
}
