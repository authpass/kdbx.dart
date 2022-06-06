import 'dart:typed_data';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:pointycastle/export.dart' as pc;

/// Dart-only implementation using pointycastle's Argon KDF.
class PointyCastleArgon2 extends Argon2 {
  const PointyCastleArgon2();

  @override
  bool get isFfi => false;

  @override
  bool get isImplemented => true;

  pc.KeyDerivator argon2Kdf() => pc.Argon2BytesGenerator();

  @override
  Uint8List argon2(Argon2Arguments args) {
    final kdf = argon2Kdf();
    kdf.init(pc.Argon2Parameters(
      args.type,
      args.salt,
      desiredKeyLength: args.length,
      iterations: args.iterations,
      memory: args.memory,
      lanes: args.parallelism,
      version: args.version,
    ));
    return kdf.process(args.key);
  }

  @override
  Future<Uint8List> argon2Async(Argon2Arguments args) {
    return Future.value(argon2(args));
  }
}
