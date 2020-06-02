// ignore_for_file: non_constant_identifier_names

//typedef HashStuff = Pointer<Utf8> Function(Pointer<Utf8> str);
import 'dart:ffi';
import 'dart:io';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';

// TODO: This should be somehow combined with the test variant
//       which also loads the requierd dylib/so files.

class Argon2Test extends Argon2Base {
  Argon2Test() {
    final argon2lib = Platform.isMacOS
        ? DynamicLibrary.open('libargon2_ffi.dylib')
        : DynamicLibrary.open('./libargon2_ffi.so');
    argon2hash = argon2lib
        .lookup<NativeFunction<Argon2HashNative>>('hp_argon2_hash')
        .asFunction();
  }

  @override
  Argon2Hash argon2hash;
}
