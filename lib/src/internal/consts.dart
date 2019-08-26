import 'package:kdbx/src/kdbx_object.dart';

enum Cipher {
  aes,
  chaCha20,
}

class CryptoConsts {
  static const CIPHER_IDS = <Cipher, KdbxUuid>{
    Cipher.aes: KdbxUuid('McHy5r9xQ1C+WAUhavxa/w=='),
    Cipher.chaCha20: KdbxUuid('1gOKK4tvTLWlJDOaMdu1mg=='),
  };
}
