import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart' as convert;
import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/crypto/protected_salt_generator.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/internal/crypto_utils.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';
import 'package:xml/xml.dart' as xml;

import 'kdbx_object.dart';

final _logger = Logger('kdbx.format');

abstract class Credentials {
  factory Credentials(ProtectedValue password) => PasswordCredentials(password);

  Credentials._();

  factory Credentials.fromHash(Uint8List hash) => HashCredentials(hash);

  Uint8List getHash();
}

class PasswordCredentials implements Credentials {
  PasswordCredentials(this._password);

  final ProtectedValue _password;

  @override
  Uint8List getHash() {
    final output = convert.AccumulatorSink<crypto.Digest>();
    final input = crypto.sha256.startChunkedConversion(output);
    input.add(_password.hash);
    input.close();
    return output.events.single.bytes as Uint8List;
  }
}

class HashCredentials implements Credentials {
  HashCredentials(this.hash);

  final Uint8List hash;

  @override
  Uint8List getHash() => hash;
}

class KdbxFile {
  KdbxFile(this.credentials, this.header, this.body) {
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

  final Credentials credentials;
  final KdbxHeader header;
  final KdbxBody body;
  final Set<KdbxObject> dirtyObjects = {};
  final StreamController<Set<KdbxObject>> _dirtyObjectsChanged =
      StreamController<Set<KdbxObject>>.broadcast();
  Stream<Set<KdbxObject>> get dirtyObjectsChanged =>
      _dirtyObjectsChanged.stream;

  Uint8List save() {
    assert(header.versionMajor == 3);
    final output = BytesBuilder();
    final writer = WriterHelper(output);
    header.generateSalts();
    header.write(writer);

    final streamKey =
        header.fields[HeaderFields.ProtectedStreamKey].bytes.asUint8List();
    final gen = ProtectedSaltGenerator(streamKey);

    body.meta.headerHash.set(
        (crypto.sha256.convert(writer.output.toBytes()).bytes as Uint8List)
            .buffer);
    body.writeV3(writer, this, gen);
    dirtyObjects.clear();
    _dirtyObjectsChanged.add(dirtyObjects);
    return output.toBytes();
  }

  Iterable<KdbxObject> get _allObjects => body.rootGroup
      .getAllGroups()
      .cast<KdbxObject>()
      .followedBy(body.rootGroup.getAllEntries());

  void dirtyObject(KdbxObject kdbxObject) {
    dirtyObjects.add(kdbxObject);
    dirtyObjects.clear();
  }

  void dispose() {
    _dirtyObjectsChanged.close();
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

class KdbxBody extends KdbxNode {
  KdbxBody.create(this.meta, this.rootGroup) : super.create('KeePassFile') {
    node.children.add(meta.node);
    final rootNode = xml.XmlElement(xml.XmlName('Root'));
    node.children.add(rootNode);
    rootNode.children.add(rootGroup.node);
  }

  KdbxBody.read(xml.XmlElement node, this.meta, this.rootGroup)
      : super.read(node);

//  final xml.XmlDocument xmlDocument;
  final KdbxMeta meta;
  final KdbxGroup rootGroup;

  void writeV3(WriterHelper writer, KdbxFile kdbxFile,
      ProtectedSaltGenerator saltGenerator) {
    final xml = generateXml(saltGenerator);
    final xmlBytes = utf8.encode(xml.toXmlString());
    final Uint8List compressedBytes =
        (kdbxFile.header.compression == Compression.gzip
            ? GZipCodec().encode(xmlBytes)
            : xmlBytes) as Uint8List;

    final encrypted = _encryptV3(kdbxFile, compressedBytes);
    writer.writeBytes(encrypted);
  }

  Uint8List _encryptV3(KdbxFile kdbxFile, Uint8List compressedBytes) {
    final byteWriter = WriterHelper();
    byteWriter.writeBytes(kdbxFile
        .header.fields[HeaderFields.StreamStartBytes].bytes
        .asUint8List());
    HashedBlockReader.writeBlocks(ReaderHelper(compressedBytes), byteWriter);
    final bytes = byteWriter.output.toBytes();

    final masterKey =
        KdbxFormat._generateMasterKeyV3(kdbxFile.header, kdbxFile.credentials);
    final encrypted = KdbxFormat._encryptDataAes(masterKey, bytes,
        kdbxFile.header.fields[HeaderFields.EncryptionIV].bytes.asUint8List());
    return encrypted;
  }

  xml.XmlDocument generateXml(ProtectedSaltGenerator saltGenerator) {
    final rootGroupNode = rootGroup.toXml();
    // update protected values...
    for (final el in rootGroupNode.findAllElements(KdbxXml.NODE_VALUE).where(
        (el) =>
            el.getAttribute(KdbxXml.ATTR_PROTECTED)?.toLowerCase() == 'true')) {
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
        'xml', 'version="1.0" encoding="utf-8" standalone="yes"');
    builder.element(
      'KeePassFile',
      nest: [
        meta.toXml(),
        () => builder.element('Root', nest: rootGroupNode),
      ],
    );
//    final doc = xml.XmlDocument();
//    doc.children.add(xml.XmlProcessing(
//        'xml', 'version="1.0" encoding="utf-8" standalone="yes"'));
    final node = builder.build() as xml.XmlDocument;

    return node;
  }
}

class KdbxMeta extends KdbxNode {
  KdbxMeta.create({@required String databaseName}) : super.create('Meta') {
    this.databaseName.set(databaseName);
  }

  KdbxMeta.read(xml.XmlElement node) : super.read(node);

  StringNode get databaseName => StringNode(this, 'DatabaseName');

  Base64Node get headerHash => Base64Node(this, 'HeaderHash');

  @override
  // ignore: unnecessary_overrides
  xml.XmlElement toXml() {
    return super.toXml();
  }
}

class KdbxFormat {
  static KdbxFile create(Credentials credentials, String name) {
    final header = KdbxHeader.create();
    final meta = KdbxMeta.create(databaseName: name);
    final rootGroup = KdbxGroup.create(parent: null, name: name);
    final body = KdbxBody.create(meta, rootGroup);
    return KdbxFile(credentials, header, body);
  }

  static KdbxFile read(Uint8List input, Credentials credentials) {
    final reader = ReaderHelper(input);
    final header = KdbxHeader.read(reader);
    return _loadV3(header, reader, credentials);
  }

  static KdbxFile _loadV3(
      KdbxHeader header, ReaderHelper reader, Credentials credentials) {
//    _getMasterKeyV3(header, credentials);
    final masterKey = _generateMasterKeyV3(header, credentials);
    final encryptedPayload = reader.readRemaining();
    final content = _decryptContent(header, masterKey, encryptedPayload);
    final blocks = HashedBlockReader.readBlocks(ReaderHelper(content));

    _logger.finer('compression: ${header.compression}');
    if (header.compression == Compression.gzip) {
      final xml = GZipCodec().decode(blocks);
      final string = utf8.decode(xml);
      return KdbxFile(credentials, header, _loadXml(header, string));
    } else {
      return KdbxFile(
          credentials, header, _loadXml(header, utf8.decode(blocks)));
    }
  }

  static KdbxBody _loadXml(KdbxHeader header, String xmlString) {
    final protectedValueEncryption = header.innerRandomStreamEncryption;
    if (protectedValueEncryption != ProtectedValueEncryption.salsa20) {
      throw KdbxUnsupportedException(
          'Inner encryption: $protectedValueEncryption');
    }
    final streamKey =
        header.fields[HeaderFields.ProtectedStreamKey].bytes.asUint8List();
    final gen = ProtectedSaltGenerator(streamKey);

    final document = xml.parse(xmlString);

    for (final el in document
        .findAllElements('Value')
        .where((el) => el.getAttribute('Protected')?.toLowerCase() == 'true')) {
      final pw = gen.decryptBase64(el.text.trim());
      KdbxFile.protectedValues[el] = ProtectedValue.fromString(pw);
    }

    final keePassFile = document.findElements('KeePassFile').single;
    final meta = keePassFile.findElements('Meta').single;
    final root = keePassFile.findElements('Root').single;
    final rootGroup = KdbxGroup.read(null, root.findElements('Group').single);
    _logger.fine('got meta: ${meta.toXmlString(pretty: true)}');
    return KdbxBody.read(keePassFile, KdbxMeta.read(meta), rootGroup);
  }

  static Uint8List _decryptContent(
      KdbxHeader header, Uint8List masterKey, Uint8List encryptedPayload) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final decryptCipher = CBCBlockCipher(AESFastEngine());
    decryptCipher.init(false,
        ParametersWithIV(KeyParameter(masterKey), encryptionIv.asUint8List()));
    final paddedDecrypted =
        AesHelper.processBlocks(decryptCipher, encryptedPayload);
    final decrypted = AesHelper.unpad(paddedDecrypted);

    final streamStart = header.fields[HeaderFields.StreamStartBytes].bytes;

    _logger.finest(
        'streamStart: ${ByteUtils.toHexList(streamStart.asUint8List())}');
    _logger.finest(
        'actual     : ${ByteUtils.toHexList(decrypted.sublist(0, streamStart.lengthInBytes))}');

    if (!ByteUtils.eq(streamStart.asUint8List(),
        decrypted.sublist(0, streamStart.lengthInBytes))) {
      throw KdbxInvalidKeyException();
    }
    // ignore: unnecessary_cast
    final content = decrypted.sublist(streamStart.lengthInBytes) as Uint8List;
    return content;
  }

  static Uint8List _generateMasterKeyV3(
      KdbxHeader header, Credentials credentials) {
    final rounds =
        header.fields[HeaderFields.TransformRounds].bytes.asUint64List().first;
    final seed = header.fields[HeaderFields.TransformSeed].bytes.asUint8List();
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    _logger.finer('Rounds: $rounds');

    final cipher = ECBBlockCipher(AESFastEngine())
      ..init(true, KeyParameter(seed));
    final pwHash = credentials.getHash();
    var transformedKey = pwHash;
    for (int i = 0; i < rounds; i++) {
      transformedKey = AesHelper.processBlocks(cipher, transformedKey);
    }
    transformedKey = crypto.sha256.convert(transformedKey).bytes as Uint8List;
    final masterKey = crypto.sha256
        .convert(Uint8List.fromList(masterSeed.asUint8List() + transformedKey))
        .bytes as Uint8List;
    return masterKey;
  }

  static Uint8List _encryptDataAes(
      Uint8List masterKey, Uint8List payload, Uint8List encryptionIv) {
    final encryptCipher = CBCBlockCipher(AESFastEngine());
    encryptCipher.init(
        true, ParametersWithIV(KeyParameter(masterKey), encryptionIv));
    return AesHelper.processBlocks(
        encryptCipher, AesHelper.pad(payload, encryptCipher.blockSize));
  }
}
