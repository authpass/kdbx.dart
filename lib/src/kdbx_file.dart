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
  }

  static final protectedValues = Expando<ProtectedValue>();

  static ProtectedValue? protectedValueForNode(xml.XmlElement node) {
    return protectedValues[node];
  }

  static void setProtectedValueForNode(
      xml.XmlElement node, ProtectedValue? value) {
    protectedValues[node] = value;
  }

  final KdbxFormat kdbxFormat;
  final KdbxReadWriteContext ctx;
  Credentials get credentials => _credentials;
  set credentials(Credentials credentials) {
    body.meta.modify(() => _credentials = credentials);
  }

  Credentials _credentials;
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
      _logger.severe('Inconsistency error, uuid $uuid not found in groups.', e,
          stackTrace);
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
          'Root groups of source and dest file do not match.');
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
