import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:ffi_helper/ffi_helper.dart';
import 'package:meta/meta.dart';

typedef Argon2HashNative = Pointer<Utf8> Function(
  Pointer<Uint8> key,
  IntPtr keyLen,
  Pointer<Uint8> salt,
  Uint64 saltlen,
  Uint32 m_cost, // memory cost
  Uint32 t_cost, // time cost (number iterations)
  Uint32 parallelism,
  IntPtr hashlen,
  Uint8 type,
  Uint32 version,
);

typedef Argon2Hash = Pointer<Utf8> Function(
  Pointer<Uint8> key,
  int keyLen,
  Pointer<Uint8> salt,
  int saltlen,
  int m_cost, // memory cost
  int t_cost, // time cost (number iterations)
  int parallelism,
  int hashlen,
  int type,
  int version,
);

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

abstract class Argon2Base extends Argon2 {
  @protected
  Argon2Hash get argon2hash;

  @override
  Uint8List argon2(
    Uint8List key,
    Uint8List salt,
    int memory,
    int iterations,
    int length,
    int parallelism,
    int type,
    int version,
  ) {
    final keyArray = Uint8Array.fromTypedList(key);
//    final saltArray = Uint8Array.fromTypedList(salt);
    final saltArray = allocate<Uint8>(count: salt.length);
    final saltList = saltArray.asTypedList(length);
    saltList.setAll(0, salt);
//    const memoryCost = 1 << 16;

//    _logger.fine('saltArray: ${ByteUtils.toHexList(saltArray.view)}');

    final result = argon2hash(
      keyArray.rawPtr,
      keyArray.length,
      saltArray,
      salt.length,
      memory,
      iterations,
      parallelism,
      length,
      type,
      version,
    );

    keyArray.free();
//    saltArray.free();
    free(saltArray);
    final resultString = Utf8.fromUtf8(result);
    return base64.decode(resultString);
  }
}
