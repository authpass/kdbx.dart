import 'dart:convert';
import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/kdbx_var_dictionary.dart';
import 'package:logging/logging.dart';

final _logger = Logger('key_encrypter_kdf');

enum KdfType {
  Argon2,
  Aes,
}

class KdfField<T> {
  KdfField(this.field, this.type);

  final String field;
  final ValueType<T> type;

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

  final Argon2 argon2;

  Uint8List encrypt(Uint8List key, VarDictionary kdfParameters) {
    final uuid = kdfParameters.get(ValueType.typeBytes, '\$UUID');
    if (uuid == null) {
      throw KdbxCorruptedFileException('No Kdf UUID');
    }
    final kdfUuid = base64.encode(uuid);
    switch (kdfUuids[kdfUuid]) {
      case KdfType.Argon2:
        _logger.fine('Must be using argon2');
        return encryptArgon2(key, kdfParameters);
        break;
      case KdfType.Aes:
        _logger.fine('Must be using aes');
        break;
    }
    throw UnsupportedError('unsupported encrypt stuff.');
  }

  Uint8List encryptArgon2(Uint8List key, VarDictionary kdfParameters) {
    _logger.fine('argon2():');
    _logger.fine('key: ${ByteUtils.toHexList(key)}');
    KdfField.debugAll(kdfParameters);
    return argon2.argon2(
      key,
      KdfField.salt.read(kdfParameters),
      65536, //KdfField.memory.read(kdfParameters),
      KdfField.iterations.read(kdfParameters),
      32,
      KdfField.parallelism.read(kdfParameters),
      0,
      KdfField.version.read(kdfParameters),
    );
  }
}

abstract class Argon2 {
  Uint8List argon2(
    Uint8List key,
    Uint8List salt,
    int memory,
    int iterations,
    int length,
    int parallelism,
    int type,
    int version,
  );
}
