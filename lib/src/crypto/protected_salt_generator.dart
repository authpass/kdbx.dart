import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class ProtectedSaltGenerator {
  factory ProtectedSaltGenerator(Uint8List key) {
    final hash = sha256.convert(key).bytes as Uint8List;
    final cipher = Salsa20Engine()
      ..init(false, ParametersWithIV(KeyParameter(hash), salsaNonce));
    return ProtectedSaltGenerator._(cipher);
  }

  ProtectedSaltGenerator._(this._cipher);

  static final salsaNonce =
      Uint8List.fromList([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);
  final StreamCipher _cipher;

  String decryptBase64(String protectedValue) {
    final bytes = base64.decode(protectedValue);
    final result = _cipher.process(bytes);
    final decrypted = utf8.decode(result);
    return decrypted;
  }

  String encryptToBase64(String plainValue) {
    final encrypted = _cipher.process(utf8.encode(plainValue) as Uint8List);
    return base64.encode(encrypted);
  }
}
