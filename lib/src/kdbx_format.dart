import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/internal/crypto_utils.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/export.dart';

final _logger = Logger('kdbx.format');


class KdbxFormat {
  static Future<void> read(Uint8List input, Credentials credentials) async {
    final reader = ReaderHelper(input);
    final header = await KdbxHeader.read(reader);
    _loadV3(header, reader, credentials);
  }

  static void _loadV3(KdbxHeader header, ReaderHelper reader, Credentials credentials) {
//    _getMasterKeyV3(header, credentials);
    final masterKey = _generateMasterKeyV3(header, credentials);
    final encryptedPayload = reader.readRemaining();
    final content = _decryptContent(header, masterKey, encryptedPayload);
    final blocks = HashedBlockReader.readBlocks(ReaderHelper(content));

    _logger.finer('compression: ${header.compression}');
    if (header.compression == Compression.gzip) {
      final xml = GZipCodec().decode(blocks);
      final string = utf8.decode(xml);
      print('xml: $string');
    }

//    final result = utf8.decode(decrypted);
//    final aesEngine = AESFastEngine();
//    aesEngine.init(true, KeyParameter(seed));
//    final key = AesHelper.deriveKey(keyComposite.bytes as Uint8List, salt: seed, iterationCount: rounds, derivedKeyLength: 32);
//    final masterKey = Uint8List.fromList(key + masterSeed.asUint8List());
//    print('key length: ${key.length} + ${masterSeed.lengthInBytes} = ${masterKey.lengthInBytes} (${masterKey.lengthInBytes} bytes)');

//    final result = AesHelper.decrypt(masterKey, reader.readRemaining());
//    print('before     : ${_toHexList(encryptedPayload)}');
  }

  static Uint8List _decryptContent(KdbxHeader header, Uint8List masterKey, Uint8List encryptedPayload) {
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    final decryptCipher = CBCBlockCipher(AESFastEngine());
    decryptCipher.init(false, ParametersWithIV(KeyParameter(masterKey), encryptionIv.asUint8List()));
    final decrypted = AesHelper.processBlocks(decryptCipher, encryptedPayload);

    final streamStart = header.fields[HeaderFields.StreamStartBytes].bytes;

    _logger.finest('streamStart: ${ByteUtils.toHexList(streamStart.asUint8List())}');
    _logger.finest('actual     : ${ByteUtils.toHexList(decrypted.sublist(0, streamStart.lengthInBytes))}');

    if (!ByteUtils.eq(streamStart.asUint8List(), decrypted.sublist(0, streamStart.lengthInBytes))) {
      throw KdbxInvalidKeyException();
    }
    final content = decrypted.sublist(streamStart.lengthInBytes);
    return content;
  }

  static Uint8List _generateMasterKeyV3(KdbxHeader header, Credentials credentials) {
    final rounds = header.fields[HeaderFields.TransformRounds].bytes.asUint64List().first;
    final seed = header.fields[HeaderFields.TransformSeed].bytes.asUint8List();
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    _logger.finer('Rounds: $rounds');

    final cipher = ECBBlockCipher(AESFastEngine())..init(true, KeyParameter(seed));
    final pwHash = credentials.getHash();
    var transformedKey = pwHash;
    for (int i = 0; i < rounds; i++) {
      transformedKey = AesHelper.processBlocks(cipher, transformedKey);
    }
    transformedKey = crypto.sha256.convert(transformedKey).bytes as Uint8List;
    final masterKey =
    crypto.sha256.convert(Uint8List.fromList(masterSeed.asUint8List() + transformedKey)).bytes as Uint8List;
    return masterKey;
  }

}
