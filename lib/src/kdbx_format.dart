import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart' as convert;
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/argon2.dart';
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
    try {
      final keyFileAsString = utf8.decode(keyFileContents);
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

  static final RegExp _hexValuePattern =
      RegExp(r'^[a-f\d]{64}', caseSensitive: false);

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
    final output = BytesBuilder();
    final writer = WriterHelper(output);
    header.generateSalts();
    header.write(writer);
    final headerHash =
        (crypto.sha256.convert(writer.output.toBytes()).bytes as Uint8List);

    if (header.versionMajor <= 3) {
      final streamKey = header.fields[HeaderFields.ProtectedStreamKey].bytes;
      final gen = ProtectedSaltGenerator(streamKey);

      body.meta.headerHash.set(headerHash.buffer);
      body.writeV3(writer, this, gen);
    } else if (header.versionMajor <= 4) {
      final headerBytes = writer.output.toBytes();
      writer.writeBytes(headerHash);
      final gen = kdbxFormat._createProtectedSaltGenerator(header);
      final keys = await kdbxFormat._computeKeysV4(header, credentials);
      final headerHmac = kdbxFormat._getHeaderHmac(headerBytes, keys.hmacKey);
      writer.writeBytes(headerHmac.bytes as Uint8List);
      body.writeV4(writer, this, gen, keys);
    } else {
      throw UnsupportedError('Unsupported version ${header.versionMajor}');
    }
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

  void writeV4(WriterHelper writer, KdbxFile kdbxFile,
      ProtectedSaltGenerator saltGenerator, _KeysV4 keys) {
    final bodyWriter = WriterHelper();
    final xml = generateXml(saltGenerator);
    kdbxFile.header.writeInnerHeader(bodyWriter);
    bodyWriter.writeBytes(utf8.encode(xml.toXmlString()) as Uint8List);
    final Uint8List compressedBytes =
        (kdbxFile.header.compression == Compression.gzip
            ? GZipCodec().encode(bodyWriter.output.toBytes())
            : bodyWriter.output.toBytes()) as Uint8List;
    final encrypted = _encryptV4(
      kdbxFile,
      compressedBytes,
      keys.cipherKey,
    );
    final transformed = kdbxFile.kdbxFormat
        .hmacBlockTransformerEncrypt(keys.hmacKey, encrypted);
    writer.writeBytes(transformed);
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

  Uint8List _encryptV4(
      KdbxFile kdbxFile, Uint8List compressedBytes, Uint8List cipherKey) {
    final header = kdbxFile.header;
    final cipherId = base64.encode(header.fields[HeaderFields.CipherID].bytes);
    if (cipherId == CryptoConsts.CIPHER_IDS[Cipher.aes].uuid) {
      _logger.fine('We need AES');
      final result = kdbxFile.kdbxFormat
          ._encryptContentV4Aes(header, cipherKey, compressedBytes);
//      _logger.fine('Result: ${ByteUtils.toHexList(result)}');
      return result;
    } else if (cipherId == CryptoConsts.CIPHER_IDS[Cipher.chaCha20].uuid) {
      _logger.fine('We need chacha20');
      return kdbxFile.kdbxFormat
          .transformContentV4ChaCha20(header, compressedBytes, cipherKey);
    } else {
      throw UnsupportedError('Unsupported cipherId $cipherId');
    }
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

class _KeysV4 {
  _KeysV4(this.hmacKey, this.cipherKey);

  final Uint8List hmacKey;
  final Uint8List cipherKey;
}

class KdbxFormat {
  KdbxFormat([this.argon2]);

  final Argon2 argon2;

  KdbxFile create(
    Credentials credentials,
    String name, {
    String generator,
    KdbxHeader header,
  }) {
    final meta = KdbxMeta.create(
      databaseName: name,
      generator: generator,
    );
    final rootGroup = KdbxGroup.create(parent: null, name: name);
    final body = KdbxBody.create(meta, rootGroup);
    return KdbxFile(
      this,
      credentials,
      header ?? KdbxHeader.create(),
      body,
    );
  }

  Future<KdbxFile> read(Uint8List input, Credentials credentials) async {
    final reader = ReaderHelper(input);
    final header = KdbxHeader.read(reader);
    if (header.versionMajor == 3) {
      return _loadV3(header, reader, credentials);
    } else if (header.versionMajor == 4) {
      return await _loadV4(header, reader, credentials);
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
      return KdbxFile(this, credentials, header, _loadXml(header, string));
    } else {
      return KdbxFile(
          this, credentials, header, _loadXml(header, utf8.decode(blocks)));
    }
  }

  Future<KdbxFile> _loadV4(
      KdbxHeader header, ReaderHelper reader, Credentials credentials) async {
    final headerBytes = reader.byteData.sublist(0, header.endPos);
    final hash = crypto.sha256.convert(headerBytes).bytes;
    final actualHash = reader.readBytes(hash.length);
    if (!ByteUtils.eq(hash, actualHash)) {
      _logger.fine('Does not match ${ByteUtils.toHexList(hash)} '
          'vs ${ByteUtils.toHexList(actualHash)}');
      throw KdbxCorruptedFileException('Header hash does not match.');
    }
//    _logger
//        .finest('KdfParameters: ${header.readKdfParameters.toDebugString()}');
    _logger.finest('Header hash matches.');
    final keys = await _computeKeysV4(header, credentials);
    final headerHmac =
        _getHeaderHmac(reader.byteData.sublist(0, header.endPos), keys.hmacKey);
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
      final content = GZipCodec().decode(decrypted) as Uint8List;
      final contentReader = ReaderHelper(content);
      final headerFields = KdbxHeader.readInnerHeaderFields(contentReader, 4);
//      _logger.fine('inner header fields: $headerFields');
      header.innerFields.addAll(headerFields);
      final xml = utf8.decode(contentReader.readRemaining());
      return KdbxFile(this, credentials, header, _loadXml(header, xml));
    }
    throw StateError('Kdbx4 without compression is not yet supported.');
  }

  Uint8List hmacBlockTransformerEncrypt(Uint8List hmacKey, Uint8List data) {
    final writer = WriterHelper();
    final reader = ReaderHelper(data);
    const blockSize = 1024 * 1024;
    int blockIndex = 0;
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
      Uint8List hmacKey, int blockIndex, Uint8List blockData) {
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
    int blockIndex = 0;
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
      KdbxHeader header, Uint8List encrypted, Uint8List cipherKey) {
    final cipherId = base64.encode(header.fields[HeaderFields.CipherID].bytes);
    if (cipherId == CryptoConsts.CIPHER_IDS[Cipher.aes].uuid) {
      _logger.fine('We need AES');
      final result = _decryptContentV4(header, cipherKey, encrypted);
      return result;
    } else if (cipherId == CryptoConsts.CIPHER_IDS[Cipher.chaCha20].uuid) {
      _logger.fine('We need chacha20');
//      throw UnsupportedError('chacha20 not yet supported $cipherId');
      return transformContentV4ChaCha20(header, encrypted, cipherKey);
    } else {
      throw UnsupportedError('Unsupported cipherId $cipherId');
    }
  }

  Uint8List transformContentV4ChaCha20(
      KdbxHeader header, Uint8List encrypted, Uint8List cipherKey) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final key = cryptography.SecretKey(cipherKey);
    final nonce = cryptography.SecretKey(encryptionIv);
    return cryptography.chacha20.decrypt(encrypted, key, nonce: nonce);
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
      KdbxHeader header, Credentials credentials) async {
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    final kdfParameters = header.readKdfParameters;
    if (masterSeed.length != 32) {
      throw const FormatException('Master seed must be 32 bytes.');
    }

    final credentialHash = credentials.getHash();
    final key =
        await KeyEncrypterKdf(argon2).encrypt(credentialHash, kdfParameters);

//    final keyWithSeed = Uint8List(65);
//    keyWithSeed.replaceRange(0, masterSeed.length, masterSeed);
//    keyWithSeed.replaceRange(
//        masterSeed.length, masterSeed.length + key.length, key);
//    keyWithSeed[64] = 1;
    final keyWithSeed = masterSeed + key + Uint8List.fromList([1]);
    assert(keyWithSeed.length == 65);
    final cipher = crypto.sha256.convert(keyWithSeed.sublist(0, 64));
    final hmacKey = crypto.sha512.convert(keyWithSeed);

    return _KeysV4(hmacKey.bytes as Uint8List, cipher.bytes as Uint8List);
  }

  ProtectedSaltGenerator _createProtectedSaltGenerator(KdbxHeader header) {
    final protectedValueEncryption = header.innerRandomStreamEncryption;
    final streamKey = header.protectedStreamKey;
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
      if (pw == null) {
        continue;
      }
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
      KdbxHeader header, Uint8List cipherKey, Uint8List encryptedPayload) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final decryptCipher = CBCBlockCipher(AESFastEngine());
    decryptCipher.init(
        false, ParametersWithIV(KeyParameter(cipherKey), encryptionIv));
    final paddedDecrypted =
        AesHelper.processBlocks(decryptCipher, encryptedPayload);

    final decrypted = AesHelper.unpad(paddedDecrypted);
    return decrypted;
  }

  /// TODO combine this with [_decryptContentV4] (or [_encryptDataAes]?)
  Uint8List _encryptContentV4Aes(
      KdbxHeader header, Uint8List cipherKey, Uint8List bytes) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final encryptCypher = CBCBlockCipher(AESFastEngine());
    encryptCypher.init(
        true, ParametersWithIV(KeyParameter(cipherKey), encryptionIv));
    final paddedBytes = AesHelper.pad(bytes, encryptCypher.blockSize);
    return AesHelper.processBlocks(encryptCypher, paddedBytes);
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
