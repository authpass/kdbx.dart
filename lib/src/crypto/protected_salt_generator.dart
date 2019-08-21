import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class ProtectedSaltGenerator {
  factory ProtectedSaltGenerator(Uint8List key) {
    final hash = sha256.convert(key).bytes as Uint8List;
    final cipher = Salsa20Engine()..init(false, ParametersWithIV(KeyParameter(hash), SalsaNonce));
    return ProtectedSaltGenerator._(cipher);
  }

  ProtectedSaltGenerator._(this.cipher);

  static final SalsaNonce = Uint8List.fromList([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);
  final StreamCipher cipher;

  String decryptBase64(String protectedValue) {
    final bytes = base64.decode(protectedValue);
    final result = cipher.process(bytes);
    final decrypted = utf8.decode(result);
    return decrypted;
  }
}
