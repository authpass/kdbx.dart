import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/crypto/protected_salt_generator.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/internal/crypto_utils.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/export.dart';
import 'package:xml/xml.dart' as xml;

final _logger = Logger('kdbx.format');

class KdbxFile {
  KdbxFile(this.credentials, this.header, this.body);

  static final protectedValues = Expando<ProtectedValue>();

  final Credentials credentials;
  final KdbxHeader header;
  final KdbxBody body;
}

class KdbxBody {
  KdbxBody(this.xmlDocument, this.meta);

  final xml.XmlDocument xmlDocument;
  final KdbxMeta meta;
}

class KdbxMeta {

}

class KdbxFormat {

  static Future<KdbxFile> read(Uint8List input, Credentials credentials) async {
    final reader = ReaderHelper(input);
    final header = await KdbxHeader.read(reader);
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
      return KdbxFile(credentials, header, _loadXml(header, utf8.decode(blocks)));
    }
  }

  static KdbxBody _loadXml(KdbxHeader header, String xmlString) {
    final protectedValueEncryption = header.innerRandomStreamEncryption;
    if (protectedValueEncryption != PotectedValueEncryption.salsa20) {
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
    final groupRoot = keePassFile.findElements('Root').single;
    _logger.fine('got meta: ${meta.toXmlString(pretty: true)}');
    return KdbxBody(document, KdbxMeta());
  }

  static Uint8List _decryptContent(
      KdbxHeader header, Uint8List masterKey, Uint8List encryptedPayload) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final decryptCipher = CBCBlockCipher(AESFastEngine());
    decryptCipher.init(false,
        ParametersWithIV(KeyParameter(masterKey), encryptionIv.asUint8List()));
    final decrypted = AesHelper.processBlocks(decryptCipher, encryptedPayload);

    final streamStart = header.fields[HeaderFields.StreamStartBytes].bytes;

    _logger.finest(
        'streamStart: ${ByteUtils.toHexList(streamStart.asUint8List())}');
    _logger.finest(
        'actual     : ${ByteUtils.toHexList(decrypted.sublist(0, streamStart.lengthInBytes))}');

    if (!ByteUtils.eq(streamStart.asUint8List(),
        decrypted.sublist(0, streamStart.lengthInBytes))) {
      throw KdbxInvalidKeyException();
    }
    final content = decrypted.sublist(streamStart.lengthInBytes);
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
}
