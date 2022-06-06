import 'dart:typed_data';

import 'package:pointycastle/export.dart';

// ignore_for_file: omit_local_variable_types

/// https://gist.github.com/proteye/e54eef1713e1fe9123d1eb04c0a5cf9b
class AesHelper {
  static const CBC_MODE = 'CBC';
  static const CFB_MODE = 'CFB';

  // AES key size
  static const KEY_SIZE = 32; // 32 byte key for AES-256
  static const ITERATION_COUNT = 1000;

  static Uint8List deriveKey(
    Uint8List password, {
    required Uint8List salt,
    int iterationCount = ITERATION_COUNT,
    int derivedKeyLength = KEY_SIZE,
  }) {
    final Pbkdf2Parameters params =
        Pbkdf2Parameters(salt, iterationCount, derivedKeyLength);
    final KeyDerivator keyDerivator =
        PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
    keyDerivator.init(params);

    return keyDerivator.process(password);
  }

  static String decrypt(Uint8List derivedKey, Uint8List cipherIvBytes,
      {String mode = CBC_MODE}) {
//    Uint8List derivedKey = deriveKey(password);
    final KeyParameter keyParam = KeyParameter(derivedKey);
    final BlockCipher aes = AESEngine();

//    Uint8List cipherIvBytes = base64.decode(ciphertext);
    final Uint8List iv = Uint8List(aes.blockSize)
      ..setRange(0, aes.blockSize, cipherIvBytes);

    BlockCipher cipher;
    final ParametersWithIV params = ParametersWithIV(keyParam, iv);
    switch (mode) {
      case CBC_MODE:
        cipher = CBCBlockCipher(aes);
        break;
      case CFB_MODE:
        cipher = CFBBlockCipher(aes, aes.blockSize);
        break;
      default:
        throw ArgumentError('incorrect value of the "mode" parameter');
    }
    cipher.init(false, params);

    final int cipherLen = cipherIvBytes.length - aes.blockSize;
    final Uint8List cipherBytes = Uint8List(cipherLen)
      ..setRange(0, cipherLen, cipherIvBytes, aes.blockSize);
    final Uint8List paddedText = processBlocks(cipher, cipherBytes);
    final Uint8List textBytes = unpad(paddedText);

    return String.fromCharCodes(textBytes);
  }

  static Uint8List unpad(Uint8List src) {
    final pad = PKCS7Padding();
    pad.init(null);

    final int padLength = pad.padCount(src);
    final int len = src.length - padLength;

    return Uint8List(len)..setRange(0, len, src);
  }

  static Uint8List pad(Uint8List src, int blockSize) {
    final pad = PKCS7Padding();
    pad.init(null);

    final padLength = blockSize - (src.length % blockSize);
    final out = Uint8List(src.length + padLength)..setAll(0, src);
    pad.addPadding(out, src.length);

    return out;
  }

  static Uint8List processBlocks(BlockCipher cipher, Uint8List inp) {
    final out = Uint8List(inp.lengthInBytes);

    for (var offset = 0; offset < inp.lengthInBytes;) {
      offset += cipher.processBlock(inp, offset, out, offset);
    }

    return out;
  }
}
