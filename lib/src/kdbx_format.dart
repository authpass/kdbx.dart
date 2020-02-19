import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart' as convert;
import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/key_encrypter_kdf.dart';
import 'package:kdbx/src/crypto/protected_salt_generator.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/internal/consts.dart';
import 'package:kdbx/src/internal/crypto_utils.dart';
import 'package:kdbx/src/kdbx_group.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:kdbx/src/kdbx_meta.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';
import 'package:xml/xml.dart' as xml;

final _logger = Logger('kdbx.format');

abstract class Credentials {
  factory Credentials(ProtectedValue password) =>
      Credentials.composite(password, null); //PasswordCredentials(password);
  factory Credentials.composite(ProtectedValue password, Uint8List keyFile) =>
      KeyFileComposite(
        password: password == null ? null : PasswordCredentials(password),
        keyFile: keyFile == null ? null : KeyFileCredentials(keyFile),
      );

  factory Credentials.fromHash(Uint8List hash) => HashCredentials(hash);

  Uint8List getHash();
}

class KeyFileComposite implements Credentials {
  KeyFileComposite({@required this.password, @required this.keyFile});

  PasswordCredentials password;
  KeyFileCredentials keyFile;

  @override
  Uint8List getHash() {
    final buffer = [...?password?.getBinary(), ...?keyFile?.getBinary()];
    return crypto.sha256.convert(buffer).bytes as Uint8List;

//    final output = convert.AccumulatorSink<crypto.Digest>();
//    final input = crypto.sha256.startChunkedConversion(output);
////    input.add(password.getHash());
//    input.add(buffer);
//    input.close();
//    return output.events.single.bytes as Uint8List;
  }
}

abstract class CredentialsPart {
  Uint8List getBinary();
}

class KeyFileCredentials implements CredentialsPart {
  factory KeyFileCredentials(Uint8List keyFileContents) {
    final keyFileAsString = utf8.decode(keyFileContents);
    try {
      if (_hexValuePattern.hasMatch(keyFileAsString)) {
        return KeyFileCredentials._(ProtectedValue.fromBinary(
            convert.hex.decode(keyFileAsString) as Uint8List));
      }
      final xmlContent = xml.parse(keyFileAsString);
      final key = xmlContent.findAllElements('Key').single;
      final dataString = key.findElements('Data').single;
      final dataBytes = base64.decode(dataString.text);
      _logger.finer('Decoded base64 of keyfile.');
      return KeyFileCredentials._(ProtectedValue.fromBinary(dataBytes));
    } catch (e, stackTrace) {
      _logger.warning(
          'Unable to parse key file as hex or XML, use as is.', e, stackTrace);
      final bytes = crypto.sha256.convert(keyFileContents).bytes as Uint8List;
      return KeyFileCredentials._(ProtectedValue.fromBinary(bytes));
    }
  }

  KeyFileCredentials._(this._keyFileValue);

  static final RegExp _hexValuePattern = RegExp(r'/^[a-f\d]{64}$/i');

  final ProtectedValue _keyFileValue;

  @override
  Uint8List getBinary() {
    return _keyFileValue.binaryValue;
//    return crypto.sha256.convert(_keyFileValue.binaryValue).bytes as Uint8List;
  }
}

class PasswordCredentials implements CredentialsPart {
  PasswordCredentials(this._password);

  final ProtectedValue _password;

  @override
  Uint8List getBinary() {
    return _password.hash;
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

    final streamKey = header.fields[HeaderFields.ProtectedStreamKey].bytes;
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
    _dirtyObjectsChanged.add(dirtyObjects);
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
    byteWriter.writeBytes(
        kdbxFile.header.fields[HeaderFields.StreamStartBytes].bytes);
    HashedBlockReader.writeBlocks(ReaderHelper(compressedBytes), byteWriter);
    final bytes = byteWriter.output.toBytes();

    final masterKey =
        KdbxFormat._generateMasterKeyV3(kdbxFile.header, kdbxFile.credentials);
    final encrypted = KdbxFormat._encryptDataAes(masterKey, bytes,
        kdbxFile.header.fields[HeaderFields.EncryptionIV].bytes);
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

class KdbxFormat {
  KdbxFormat([this.argon2]);

  final Argon2 argon2;

  KdbxFile create(
    Credentials credentials,
    String name, {
    String generator,
  }) {
    final header = KdbxHeader.create();
    final meta = KdbxMeta.create(
      databaseName: name,
      generator: generator,
    );
    final rootGroup = KdbxGroup.create(parent: null, name: name);
    final body = KdbxBody.create(meta, rootGroup);
    return KdbxFile(credentials, header, body);
  }

  KdbxFile read(Uint8List input, Credentials credentials) {
    final reader = ReaderHelper(input);
    final header = KdbxHeader.read(reader);
    if (header.versionMajor == 3) {
      return _loadV3(header, reader, credentials);
    } else if (header.versionMajor == 4) {
      return _loadV4(header, reader, credentials);
    } else {
      _logger.finer('Unsupported version for $header');
      throw KdbxUnsupportedException('Unsupported kdbx version '
          '${header.versionMajor}.${header.versionMinor}.'
          ' Only 3.x and 4.x is supported.');
    }
  }

  KdbxFile _loadV3(
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

  KdbxFile _loadV4(
      KdbxHeader header, ReaderHelper reader, Credentials credentials) {
    final headerBytes = reader.byteData.sublist(0, header.endPos);
    final hash = crypto.sha256.convert(headerBytes).bytes;
    final actualHash = reader.readBytes(hash.length);
    if (!ByteUtils.eq(hash, actualHash)) {
      _logger.fine(
          'Does not match ${ByteUtils.toHexList(hash)} vs ${ByteUtils.toHexList(actualHash)}');
      throw KdbxCorruptedFileException('Header hash does not match.');
    }
    _logger
        .finest('KdfParameters: ${header.readKdfParameters.toDebugString()}');
    _logger.finest('Header hash matches.');
    final key = _computeKeysV4(header, credentials);
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    if (masterSeed.length != 32) {
      throw const FormatException('Master seed must be 32 bytes.');
    }
//    final keyWithSeed = Uint8List(65);
//    keyWithSeed.replaceRange(0, masterSeed.length, masterSeed);
//    keyWithSeed.replaceRange(
//        masterSeed.length, masterSeed.length + key.length, key);
//    keyWithSeed[64] = 1;
    _logger.fine('masterSeed: ${ByteUtils.toHexList(masterSeed)}');
    final keyWithSeed = masterSeed + key + Uint8List.fromList([1]);
    assert(keyWithSeed.length == 65);
    final cipher = crypto.sha256.convert(keyWithSeed.sublist(0, 64));
    final hmacKey = crypto.sha512.convert(keyWithSeed);
    _logger.fine('hmacKey: ${ByteUtils.toHexList(hmacKey.bytes)}');
    final headerHmac =
        _getHeaderHmac(header, reader, hmacKey.bytes as Uint8List);
    final expectedHmac = reader.readBytes(headerHmac.bytes.length);
    _logger.fine('Expected: ${ByteUtils.toHexList(expectedHmac)}');
    _logger.fine('Actual  : ${ByteUtils.toHexList(headerHmac.bytes)}');
    if (!ByteUtils.eq(hash, actualHash)) {
      throw KdbxInvalidKeyException();
    }
//    final hmacTransformer = crypto.Hmac(crypto.sha256, hmacKey.bytes);
//    final blockreader.readBytes(32);
    final bodyStuff = hmacBlockTransformer(reader);
    _logger.fine('body decrypt: ${ByteUtils.toHexList(bodyStuff)}');
    final decrypted = decrypt(header, bodyStuff, cipher.bytes as Uint8List);
    _logger.finer('compression: ${header.compression}');
    if (header.compression == Compression.gzip) {
      final content = GZipCodec().decode(decrypted) as Uint8List;
      final contentReader = ReaderHelper(content);
      final fieldIterable =
          KdbxHeader.readField(contentReader, 4, InnerHeaderFields.values);
      final headerFields = Map.fromEntries(
          fieldIterable.map((field) => MapEntry(field.field, field)));
      _logger.fine('inner header fields: $headerFields');
      header.fields.addAll(headerFields);
      final xml = utf8.decode(contentReader.readRemaining());
      _logger.fine('content: $xml');
      return KdbxFile(credentials, header, _loadXml(header, xml));
    }
    return null;
  }

  Uint8List hmacBlockTransformer(ReaderHelper reader) {
    Uint8List blockHash;
    int blockLength;
    List<int> ret = <int>[];
    while (true) {
      blockHash = reader.readBytes(32);
      blockLength = reader.readUint32();
      if (blockLength < 1) {
        return Uint8List.fromList(ret);
      }
      ret.addAll(reader.readBytes(blockLength));
    }
  }

  Uint8List decrypt(
      KdbxHeader header, Uint8List encrypted, Uint8List cipherKey) {
    final cipherId = base64.encode(header.fields[HeaderFields.CipherID].bytes);
    if (cipherId == CryptoConsts.CIPHER_IDS[Cipher.aes].uuid) {
      _logger.fine('We need AES');
      final result = _decryptContentV4(header, cipherKey, encrypted);
      _logger.fine('Result: ${ByteUtils.toHexList(result)}');
      return result;
    } else if (cipherId == CryptoConsts.CIPHER_IDS[Cipher.chaCha20].uuid) {
      _logger.fine('We need chacha20');
    } else {
      throw UnsupportedError('Unsupported cipherId $cipherId');
    }
  }

//  Uint8List _transformDataV4Aes() {
//  }

  crypto.Digest _getHeaderHmac(
      KdbxHeader header, ReaderHelper reader, Uint8List key) {
    final writer = WriterHelper()
      ..writeUint32(0xffffffff)
      ..writeUint32(0xffffffff)
      ..writeBytes(key);
    final hmacKey = crypto.sha512.convert(writer.output.toBytes()).bytes;
    final src = reader.byteData.sublist(0, header.endPos);
    final hmacKeyStuff = crypto.Hmac(crypto.sha256, hmacKey);
    _logger.fine('keySha: ${ByteUtils.toHexList(hmacKey)}');
    _logger.fine('src: ${ByteUtils.toHexList(src)}');
    return hmacKeyStuff.convert(src);
  }

  Uint8List _computeKeysV4(KdbxHeader header, Credentials credentials) {
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    final kdfParameters = header.readKdfParameters;
    assert(masterSeed.length == 32);
    final credentialHash = credentials.getHash();
    _logger.fine('MasterSeed: ${ByteUtils.toHexList(masterSeed)}');
    _logger.fine('credentialHash: ${ByteUtils.toHexList(credentialHash)}');
    final ret = KeyEncrypterKdf(argon2).encrypt(credentialHash, kdfParameters);
    _logger.fine('keyv4: ${ByteUtils.toHexList(ret)}');
    return ret;
  }

  ProtectedSaltGenerator _createProtectedSaltGenerator(KdbxHeader header) {
    final protectedValueEncryption = header.innerRandomStreamEncryption;
    final streamKey = header.fields[HeaderFields.ProtectedStreamKey].bytes;
    if (protectedValueEncryption == ProtectedValueEncryption.salsa20) {
      return ProtectedSaltGenerator(streamKey);
    } else if (protectedValueEncryption == ProtectedValueEncryption.chaCha20) {
      return ProtectedSaltGenerator.chacha20(streamKey);
    } else {
      throw KdbxUnsupportedException(
          'Inner encryption: $protectedValueEncryption');
    }
  }

  KdbxBody _loadXml(KdbxHeader header, String xmlString) {
    final gen = _createProtectedSaltGenerator(header);

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

  Uint8List _decryptContent(
      KdbxHeader header, Uint8List masterKey, Uint8List encryptedPayload) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final decryptCipher = CBCBlockCipher(AESFastEngine());
    decryptCipher.init(
        false, ParametersWithIV(KeyParameter(masterKey), encryptionIv));
    final paddedDecrypted =
        AesHelper.processBlocks(decryptCipher, encryptedPayload);

    final streamStart = header.fields[HeaderFields.StreamStartBytes].bytes;

    if (paddedDecrypted.lengthInBytes < streamStart.lengthInBytes) {
      _logger.warning(
          'decrypted content was shorter than expected stream start block.');
      throw KdbxInvalidKeyException();
    }

    _logger.finest('streamStart: ${ByteUtils.toHexList(streamStart)}');
    _logger.finest(
        'actual     : ${ByteUtils.toHexList(paddedDecrypted.sublist(0, streamStart.lengthInBytes))}');

    if (!ByteUtils.eq(
        streamStart, paddedDecrypted.sublist(0, streamStart.lengthInBytes))) {
      throw KdbxInvalidKeyException();
    }

    final decrypted = AesHelper.unpad(paddedDecrypted);

    // ignore: unnecessary_cast
    final content = decrypted.sublist(streamStart.lengthInBytes) as Uint8List;
    return content;
  }

  Uint8List _decryptContentV4(
      KdbxHeader header, Uint8List masterKey, Uint8List encryptedPayload) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final decryptCipher = CBCBlockCipher(AESFastEngine());
    decryptCipher.init(
        false, ParametersWithIV(KeyParameter(masterKey), encryptionIv));
    final paddedDecrypted =
        AesHelper.processBlocks(decryptCipher, encryptedPayload);

    final decrypted = AesHelper.unpad(paddedDecrypted);
    return decrypted;
  }

  static Uint8List _generateMasterKeyV3(
      KdbxHeader header, Credentials credentials) {
    final rounds = ReaderHelper.singleUint64(
        header.fields[HeaderFields.TransformRounds].bytes);
    final seed = header.fields[HeaderFields.TransformSeed].bytes;
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    _logger.finer(
        'Rounds: $rounds (${ByteUtils.toHexList(header.fields[HeaderFields.TransformRounds].bytes)})');

    final cipher = ECBBlockCipher(AESFastEngine())
      ..init(true, KeyParameter(seed));
    final pwHash = credentials.getHash();
    var transformedKey = pwHash;
    for (int i = 0; i < rounds; i++) {
      transformedKey = AesHelper.processBlocks(cipher, transformedKey);
    }
    transformedKey = crypto.sha256.convert(transformedKey).bytes as Uint8List;
    final masterKey = crypto.sha256
        .convert(Uint8List.fromList(masterSeed + transformedKey))
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
