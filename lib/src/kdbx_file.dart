import 'dart:async';
import 'dart:typed_data';

import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:logging/logging.dart';
import 'package:xml/xml.dart' as xml;
import 'package:kdbx/src/kdbx_dao.dart';

final _logger = Logger('kdbx_file');

class KdbxFile {
  KdbxFile(this.kdbxFormat, this.credentials, this.header, this.body) {
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

  KdbxGroup _recycleBin;

  /// Returns the recycle bin, if it exists, null otherwise.
  KdbxGroup get recycleBin => _recycleBin ??= _findRecycleBin();

  KdbxGroup _findRecycleBin() {
    final uuid = body.meta.recycleBinUUID.get();
    if (uuid?.isNil != false) {
      return null;
    }
    try {
      return findGroupByUuid(uuid);
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
      rethrow;
    }
  }

//  void _subscribeToChildren() {
//    final allObjects = _allObjects;
//    for (final obj in allObjects) {
//      _subscriptions.handle(obj.changes.listen((event) {
//        if (event.isDirty) {
//          isDirty = true;
//          if (event.object is KdbxGroup) {
//            Future(() {
//              // resubscribe, just in case some child groups/entries have changed.
//              _subscriptions.cancelSubscriptions();
//              _subscribeToChildren();
//            });
//          }
//        }
//      }));
//    }
//  }
}
