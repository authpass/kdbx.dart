import 'dart:async';
import 'dart:typed_data';

import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_consts.dart';
import 'package:kdbx/src/kdbx_dao.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:logging/logging.dart';
import 'package:xml/xml.dart' as xml;

final _logger = Logger('kdbx_file');

class KdbxFile {
  KdbxFile(
      this.ctx, this.kdbxFormat, this.credentials, this.header, this.body) {
    for (final obj in _allObjects) {
      obj.file = this;
    }
  }

  static final protectedValues = Expando<ProtectedValue>();

  static ProtectedValue protectedValueForNode(xml.XmlElement node) {
    return protectedValues[node];
  }

  static void setProtectedValueForNode(
      xml.XmlElement node, ProtectedValue value) {
    protectedValues[node] = value;
  }

  final KdbxFormat kdbxFormat;
  final KdbxReadWriteContext ctx;
  final Credentials credentials;
  final KdbxHeader header;
  final KdbxBody body;
  final Set<KdbxObject> dirtyObjects = {};
  final StreamController<Set<KdbxObject>> _dirtyObjectsChanged =
      StreamController<Set<KdbxObject>>.broadcast();

  Stream<Set<KdbxObject>> get dirtyObjectsChanged =>
      _dirtyObjectsChanged.stream;

  Future<Uint8List> save() async {
    return kdbxFormat.save(this);
  }

  /// Marks all dirty objects as clean. Called by [KdbxFormat.save].
  void onSaved() {
    dirtyObjects.clear();
    _dirtyObjectsChanged.add(dirtyObjects);
  }

  Iterable<KdbxObject> get _allObjects => body.rootGroup
      .getAllGroups()
      .cast<KdbxObject>()
      .followedBy(body.rootGroup.getAllEntries());

  void dirtyObject(KdbxObject kdbxObject) {
    dirtyObjects.add(kdbxObject);
    _dirtyObjectsChanged.add(dirtyObjects);
  }

  void dispose() {
    _dirtyObjectsChanged.close();
  }

  CachedValue<KdbxGroup> _recycleBin;

  /// Returns the recycle bin, if it exists, null otherwise.
  KdbxGroup get recycleBin => (_recycleBin ??= _findRecycleBin()).value;

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
}

class CachedValue<T> {
  CachedValue.withNull() : value = null;
  CachedValue.withValue(this.value) : assert(value != null);

  final T value;
}
