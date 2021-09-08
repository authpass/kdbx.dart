import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_binary.dart';
import 'package:kdbx/src/kdbx_custom_data.dart';
import 'package:kdbx/src/kdbx_exceptions.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:quiver/iterables.dart';
import 'package:xml/xml.dart' as xml;
import 'package:xml/xml.dart';

final _logger = Logger('kdbx_meta');

class KdbxMeta extends KdbxNode implements KdbxNodeContext {
  KdbxMeta.create({
    required String databaseName,
    required this.ctx,
    String? generator,
  })  : customData = KdbxCustomData.create(),
        binaries = [],
        _customIcons = {},
        super.create('Meta') {
    this.databaseName.set(databaseName);
    databaseDescription.set(null, force: true);
    defaultUserName.set(null, force: true);
    this.generator.set(generator ?? 'kdbx.dart');
    settingsChanged.setToNow();
    masterKeyChanged.setToNow();
    recycleBinChanged.setToNow();
    historyMaxItems.set(Consts.DefaultHistoryMaxItems);
    historyMaxSize.set(Consts.DefaultHistoryMaxSize);
  }

  KdbxMeta.read(xml.XmlElement node, this.ctx)
      : customData = node
                .singleElement(KdbxXml.NODE_CUSTOM_DATA)
                ?.let((e) => KdbxCustomData.read(e)) ??
            KdbxCustomData.create(),
        binaries = node
            .singleElement(KdbxXml.NODE_BINARIES)
            ?.let((el) sync* {
              for (final binaryNode in el.findElements(KdbxXml.NODE_BINARY)) {
                final id = int.parse(binaryNode.getAttribute(KdbxXml.ATTR_ID)!);
                yield MapEntry(
                  id,
                  KdbxBinary.readBinaryXml(binaryNode, isInline: false),
                );
              }
            })
            .toList()
            .let((binaries) {
              binaries.sort((a, b) => a.key.compareTo(b.key));
              for (var i = 0; i < binaries.length; i++) {
                if (i != binaries[i].key) {
                  throw KdbxCorruptedFileException(
                      'Invalid ID for binary. expected $i,'
                      ' but was ${binaries[i].key}');
                }
              }
              return binaries.map((e) => e.value).toList();
            }),
        _customIcons = node
                .singleElement(KdbxXml.NODE_CUSTOM_ICONS)
                ?.let((el) sync* {
                  for (final iconNode in el.findElements(KdbxXml.NODE_ICON)) {
                    yield KdbxCustomIcon(
                        uuid: KdbxUuid(
                            iconNode.singleTextNode(KdbxXml.NODE_UUID)),
                        data: base64.decode(
                            iconNode.singleTextNode(KdbxXml.NODE_DATA)));
                  }
                })
                .map((e) => MapEntry(e.uuid, e))
                .let((that) => Map.fromEntries(that)) ??
            {},
        super.read(node);

  @override
  final KdbxReadWriteContext ctx;

  final KdbxCustomData customData;

  /// only used in Kdbx 3
  final List<KdbxBinary>? binaries;

  final Map<KdbxUuid?, KdbxCustomIcon> _customIcons;

  Map<KdbxUuid?, KdbxCustomIcon> get customIcons =>
      UnmodifiableMapView(_customIcons);

  void addCustomIcon(KdbxCustomIcon customIcon) {
    if (_customIcons.containsKey(customIcon.uuid)) {
      return;
    }
    modify(() => _customIcons[customIcon.uuid] = customIcon);
  }

  StringNode get generator => StringNode(this, 'Generator');

  StringNode get databaseName => StringNode(this, 'DatabaseName')
    ..setOnModifyListener(() => databaseNameChanged.setToNow());
  DateTimeUtcNode get databaseNameChanged =>
      DateTimeUtcNode(this, 'DatabaseNameChanged');

  StringNode get databaseDescription => StringNode(this, 'DatabaseDescription')
    ..setOnModifyListener(() => databaseDescriptionChanged.setToNow());
  DateTimeUtcNode get databaseDescriptionChanged =>
      DateTimeUtcNode(this, 'DatabaseDescriptionChanged');

  StringNode get defaultUserName => StringNode(this, 'DefaultUserName')
    ..setOnModifyListener(() => defaultUserNameChanged.setToNow());
  DateTimeUtcNode get defaultUserNameChanged =>
      DateTimeUtcNode(this, 'DefaultUserNameChanged');

  DateTimeUtcNode get masterKeyChanged =>
      DateTimeUtcNode(this, 'MasterKeyChanged');

  Base64Node get headerHash => Base64Node(this, 'HeaderHash');

  BooleanNode get recycleBinEnabled => BooleanNode(this, 'RecycleBinEnabled');

  UuidNode get recycleBinUUID => UuidNode(this, 'RecycleBinUUID')
    ..setOnModifyListener(() => recycleBinChanged.setToNow());

  DateTimeUtcNode get settingsChanged =>
      DateTimeUtcNode(this, 'SettingsChanged');

  DateTimeUtcNode get recycleBinChanged =>
      DateTimeUtcNode(this, 'RecycleBinChanged');

  UuidNode get entryTemplatesGroup => UuidNode(this, 'EntryTemplatesGroup')
    ..setOnModifyListener(() => entryTemplatesGroupChanged.setToNow());
  DateTimeUtcNode get entryTemplatesGroupChanged =>
      DateTimeUtcNode(this, 'EntryTemplatesGroupChanged');

  IntNode get historyMaxItems => IntNode(this, 'HistoryMaxItems');

  /// max size of history in bytes.
  IntNode get historyMaxSize => IntNode(this, 'HistoryMaxSize');

  /// not sure what this node is supposed to do actually.
  IntNode get maintenanceHistoryDays => IntNode(this, 'MaintenanceHistoryDays');

//  void addCustomIcon

  @override
  xml.XmlElement toXml() {
    final ret = super.toXml()..replaceSingle(customData.toXml());
    XmlUtils.removeChildrenByName(ret, KdbxXml.NODE_BINARIES);
    // with kdbx >= 4 we assume the binaries were already written in the header.
    if (ctx.versionMajor < 4) {
      ret.children.add(
        XmlElement(XmlName(KdbxXml.NODE_BINARIES))
          ..children.addAll(
            enumerate(ctx.binariesIterable).map((indexed) {
              final xmlBinary = XmlUtils.createNode(KdbxXml.NODE_BINARY)
                ..addAttribute(KdbxXml.ATTR_ID, indexed.index.toString());
              indexed.value.saveToXml(xmlBinary);
              return xmlBinary;
            }),
          ),
      );
    }
    XmlUtils.removeChildrenByName(ret, KdbxXml.NODE_CUSTOM_ICONS);
    ret.children.add(
      XmlElement(XmlName(KdbxXml.NODE_CUSTOM_ICONS))
        ..children.addAll(customIcons.values.map(
          (e) => XmlUtils.createNode(KdbxXml.NODE_ICON, [
            XmlUtils.createTextNode(KdbxXml.NODE_UUID, e.uuid.uuid),
            XmlUtils.createTextNode(KdbxXml.NODE_DATA, base64.encode(e.data))
          ]),
        )),
    );
    return ret;
  }

  // Merge in changes in [other] into this meta data.
  void merge(KdbxMeta other) {
    // FIXME make sure this is finished
    if (other.databaseNameChanged.isAfter(databaseNameChanged)) {
      databaseName.set(other.databaseName.get());
      databaseNameChanged.set(other.databaseNameChanged.get());
    }
    if (other.databaseDescriptionChanged.isAfter(databaseDescriptionChanged)) {
      databaseDescription.set(other.databaseDescription.get());
      databaseDescriptionChanged.set(other.databaseDescriptionChanged.get());
    }
    if (other.defaultUserNameChanged.isAfter(defaultUserNameChanged)) {
      defaultUserName.set(other.defaultUserName.get());
      defaultUserNameChanged.set(other.defaultUserNameChanged.get());
    }
    if (other.masterKeyChanged.isAfter(masterKeyChanged)) {
      // throw UnimplementedError(
      //     'Other database changed master key. not supported.');
      _logger.shout('MasterKey was changed? We will not merge this (yet).');
    }
    if (other.recycleBinChanged.isAfter(recycleBinChanged)) {
      recycleBinEnabled.set(other.recycleBinEnabled.get());
      recycleBinUUID.set(other.recycleBinUUID.get());
      recycleBinChanged.set(other.recycleBinChanged.get());
    }
    final otherIsNewer = other.settingsChanged.isAfter(settingsChanged);
    // merge custom data
    customData.merge(other.customData, otherIsNewer);
    // merge custom icons
    for (final otherCustomIcon in other._customIcons.values) {
      _customIcons[otherCustomIcon.uuid] ??= otherCustomIcon;
    }

    settingsChanged.set(other.settingsChanged.get());
  }
}

class KdbxCustomIcon {
  KdbxCustomIcon({required this.uuid, required this.data});

  /// uuid of the icon, must be unique within each file.
  final KdbxUuid uuid;

  /// Encoded png data of the image. will be base64 encoded into the kdbx file.
  final Uint8List data;
}
