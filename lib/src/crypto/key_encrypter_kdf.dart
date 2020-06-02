import 'dart:convert';
import 'dart:typed_data';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:isolate/isolate_runner.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/internal/crypto_utils.dart';
import 'package:kdbx/src/kdbx_var_dictionary.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/export.dart';

final _logger = Logger('key_encrypter_kdf');

enum KdfType {
  Argon2,
  Aes,
}

class KdfField<T> {
  KdfField(this.field, this.type);

  final String field;
  final ValueType<T> type;

  static final uuid = KdfField('\$UUID', ValueType.typeBytes);
  static final salt = KdfField('S', ValueType.typeBytes);
  static final parallelism = KdfField('P', ValueType.typeUInt32);
  static final memory = KdfField('M', ValueType.typeUInt64);
  static final iterations = KdfField('I', ValueType.typeUInt64);
  static final version = KdfField('V', ValueType.typeUInt32);
  static final secretKey = KdfField('K', ValueType.typeBytes);
  static final assocData = KdfField('A', ValueType.typeBytes);
  static final rounds = KdfField('R', ValueType.typeInt64);

  static final fields = [
    salt,
    parallelism,
    memory,
    iterations,
    version,
    secretKey,
    assocData,
    rounds
  ];

  static void debugAll(VarDictionary dict) {
    _logger
        .fine('VarDictionary{\n${fields.map((f) => f.debug(dict)).join('\n')}');
  }

  T read(VarDictionary dict) => dict.get(type, field);
  void write(VarDictionary dict, T value) => dict.set(type, field, value);
  VarDictionaryItem<T> item(T value) =>
      VarDictionaryItem<T>(field, type, value);

  String debug(VarDictionary dict) {
    final value = dict.get(type, field);
    final strValue = type == ValueType.typeBytes
        ? ByteUtils.toHexList(value as Uint8List)
        : value;
    return '$field=$strValue';
  }
}

class KeyEncrypterKdf {
  KeyEncrypterKdf(this.argon2);

  static const kdfUuids = <String, KdfType>{
    '72Nt34wpREuR96mkA+MKDA==': KdfType.Argon2,
    'ydnzmmKKRGC/dA0IwYpP6g==': KdfType.Aes,
  };
  static KdbxUuid kdfUuidForType(KdfType type) {
    final uuid =
        kdfUuids.entries.firstWhere((element) => element.value == type).key;
    return KdbxUuid(uuid);
  }

  final Argon2 argon2;

  Future<Uint8List> encrypt(Uint8List key, VarDictionary kdfParameters) async {
    final uuid = kdfParameters.get(ValueType.typeBytes, '\$UUID');
    if (uuid == null) {
      throw KdbxCorruptedFileException('No Kdf UUID');
    }
    final kdfUuid = base64.encode(uuid);
    switch (kdfUuids[kdfUuid]) {
      case KdfType.Argon2:
        _logger.fine('Must be using argon2');
        return await encryptArgon2(key, kdfParameters);
        break;
      case KdfType.Aes:
        _logger.fine('Must be using aes');
        return await encryptAes(key, kdfParameters);
    }
    throw UnsupportedError(
        'unsupported KDF Type UUID ${ByteUtils.toHexList(uuid)}.');
  }

  Future<Uint8List> encryptArgon2(
      Uint8List key, VarDictionary kdfParameters) async {
    return await argon2.argon2Async(Argon2Arguments(
      key,
      KdfField.salt.read(kdfParameters),
//      65536, //KdfField.memory.read(kdfParameters),
      KdfField.memory.read(kdfParameters) ~/ 1024,
      KdfField.iterations.read(kdfParameters),
      32,
      KdfField.parallelism.read(kdfParameters),
      0,
      KdfField.version.read(kdfParameters),
    ));
  }

  Future<Uint8List> encryptAes(
      Uint8List key, VarDictionary kdfParameters) async {
    final encryptionKey = KdfField.salt.read(kdfParameters);
    final rounds = KdfField.rounds.read(kdfParameters);
    assert(encryptionKey.length == 32);
    return await encryptAesAsync(EncryptAesArgs(encryptionKey, key, rounds));
  }

  static Future<Uint8List> encryptAesAsync(EncryptAesArgs args) async {
    final runner = await IsolateRunner.spawn();
    try {
      _logger
          .finest('Starting encryptAes for ${args.rounds} rounds in isolate.');
      return await runner.run(_encryptAesSync, args);
    } finally {
      _logger.finest('Done aes encrypt.');
      await runner.kill();
    }
  }

  static Uint8List _encryptAesSync(EncryptAesArgs args) {
    final cipher = ECBBlockCipher(AESFastEngine())
      ..init(true, KeyParameter(args.encryptionKey));
    var transformedKey = args.key;

    final rounds = args.rounds;
    for (var i = 0; i < rounds; i++) {
      transformedKey = AesHelper.processBlocks(cipher, transformedKey);
    }
    return crypto.sha256.convert(transformedKey).bytes as Uint8List;
  }
}

class EncryptAesArgs {
  EncryptAesArgs(this.encryptionKey, this.key, this.rounds);

  final Uint8List encryptionKey;
  final Uint8List key;
  final int rounds;
}
