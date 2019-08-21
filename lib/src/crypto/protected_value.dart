import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

abstract class StringValue {
  /// retrieves the (decrypted) stored value.
  String getText();
}

class PlainValue implements StringValue {
  PlainValue(this.text);

  final String text;

  @override
  String getText() {
    return text;
  }

  @override
  String toString() {
    return 'PlainValue{text: $text}';
  }

}

class ProtectedValue implements StringValue {
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
    return Uint8List.fromList(
        List.generate(length, (i) => random.nextInt(0xff)));
  }

  static Uint8List _xor(Uint8List a, Uint8List b) {
    assert(a.length == b.length);
    final ret = Uint8List(a.length);
    for (int i = 0; i < a.length; i++) {
      ret[i] = a[i] ^ b[i];
    }
    return ret;
  }

  @override
  String getText() {
    return utf8.decode(binaryValue);
  }

  @override
  String toString() {
    return 'ProtectedValue{${base64.encode(hash)}}';
  }
}
