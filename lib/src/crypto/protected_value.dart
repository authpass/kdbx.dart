import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

class ProtectedValue {
  ProtectedValue(this._value, this._salt);

  factory ProtectedValue.fromString(String value) {
    final Uint8List valueBytes = utf8.encode(value) as Uint8List;
    final Uint8List salt = _randomBytes(valueBytes.length);

    return ProtectedValue(_xor(valueBytes, salt), salt);
  }

  static final random = Random.secure();

  final Uint8List _value;
  final Uint8List _salt;

  Uint8List get binaryValue => _xor(_value, _salt);
  Uint8List get hash => sha256.convert(binaryValue).bytes as Uint8List;

  static Uint8List _randomBytes(int length) {
    return Uint8List.fromList(List.generate(length, (i) => random.nextInt(0xff)));
  }
  static Uint8List _xor(Uint8List a, Uint8List b) {
    assert(a.length == b.length);
    final ret = Uint8List(a.length);
    for (int i = 0 ; i < a.length ; i++) {
      ret[i] = a[i] ^ b[i];
    }
    return ret;
  }
}
