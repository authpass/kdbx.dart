import 'dart:typed_data';

import 'package:kdbx/src/kdbx_object.dart';

enum Cipher {
  /// the only cipher supported in kdbx <= 3
  aes,

  /// Support since kdbx 4.
  chaCha20,
}

class CryptoConsts {
  static const CIPHER_IDS = <Cipher, KdbxUuid>{
    Cipher.aes: KdbxUuid('McHy5r9xQ1C+WAUhavxa/w=='),
    Cipher.chaCha20: KdbxUuid('1gOKK4tvTLWlJDOaMdu1mg=='),
  };
  static final cipherByUuid = CIPHER_IDS.map(
    (key, value) => MapEntry(value, key),
  );

  static Cipher? cipherFromBytes(Uint8List bytes) =>
      cipherByUuid[KdbxUuid.fromBytes(bytes)];
}
