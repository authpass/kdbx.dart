import 'dart:convert';
import 'dart:typed_data';

import 'package:logging/logging.dart';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:pointycastle/export.dart';

final _logger = Logger('protected_salt_generator');

class ProtectedSaltGenerator {
  factory ProtectedSaltGenerator(Uint8List key) {
    final hash = sha256.convert(key).bytes as Uint8List;
    final cipher = Salsa20Engine()
      ..init(false, ParametersWithIV(KeyParameter(hash), salsaNonce));
    return ProtectedSaltGenerator._(cipher);
  }
  factory ProtectedSaltGenerator.chacha20(Uint8List key) {
    return ChachaProtectedSaltGenerator.create(key); // Chacha20();
  }

  ProtectedSaltGenerator._(this._cipher);

  static final salsaNonce =
      Uint8List.fromList([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);
  final StreamCipher _cipher;

  String decryptBase64(String protectedValue) {
    final bytes = base64.decode(protectedValue);
    if (bytes.isEmpty) {
      _logger.warning('decoded base64 data has length 0');
      return null;
    }
    final result = _cipher.process(bytes);
    final decrypted = utf8.decode(result);
    return decrypted;
  }

  String encryptToBase64(String plainValue) {
    final encrypted = _cipher.process(utf8.encode(plainValue) as Uint8List);
    return base64.encode(encrypted);
  }
}

class ChachaProtectedSaltGenerator implements ProtectedSaltGenerator {
  ChachaProtectedSaltGenerator._(this._secretKey, this._nonce, this._state);

  factory ChachaProtectedSaltGenerator.create(Uint8List key) {
    final hash = sha512.convert(key);
    final secretKey = hash.bytes.sublist(0, 32);
    final nonce = hash.bytes.sublist(32, 32 + 12);

    return ChachaProtectedSaltGenerator._(
        cryptography.SecretKey(secretKey),
        cryptography.SecretKey(nonce),
        cryptography.chacha20.newState(cryptography.SecretKey(secretKey),
            nonce: cryptography.SecretKey(nonce)));
  }

  final cryptography.SecretKey _secretKey;
  final cryptography.SecretKey _nonce;
  final cryptography.KeyStreamCipherState _state;

  @override
  StreamCipher get _cipher => throw UnimplementedError();

  @override
  String decryptBase64(String protectedValue) {
    final bytes = base64.decode(protectedValue);
    if (bytes.isEmpty) {
      _logger.warning('decoded base64 data has length 0');
      return null;
    }
    final result = _state.convert(bytes);
//    try {
    _logger.fine('decoding protected value.');
    final ret = utf8.decode(result);
    _logger.fine('Successfully decoded stuff.');
    return ret;
//    } on FormatException catch (e, stackTrace) {
//      final ret = utf8.decode(result, allowMalformed: true);
//      _logger.severe(
//          'Error while decoding utf8. ignoring malformed. result: {$ret}',
//          e,
//          stackTrace);
//      return ret;
//    }
  }

  @override
  String encryptToBase64(String plainValue) {
    final input = utf8.encode(plainValue) as Uint8List;
    final encrypted = _state.convert(input);
    return base64.encode(encrypted);
  }
}
