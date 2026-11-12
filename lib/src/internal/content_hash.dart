import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Builds a SHA-256 over a sequence of fields, for telling apart two versions
/// of an object which carry the same modification time.
///
/// Every field is written with its length in front, and an absent one with a
/// length no real field can have, so that neither moving bytes from one field
/// to the next nor dropping an empty field can produce the same input twice.
class ContentHashBuilder {
  final _bytes = BytesBuilder(copy: false);

  static const _absent = 0xffffffff;

  void addBytes(List<int>? bytes) {
    final length = ByteData(4)..setUint32(0, bytes?.length ?? _absent);
    _bytes.add(length.buffer.asUint8List());
    if (bytes != null) {
      _bytes.add(bytes);
    }
  }

  void addString(String? value) =>
      addBytes(value == null ? null : utf8.encode(value));

  Uint8List build() =>
      Uint8List.fromList(sha256.convert(_bytes.takeBytes()).bytes);
}

/// Orders two hashes from [ContentHashBuilder] byte by byte. The order means
/// nothing; it only has to be the same on every device.
int compareContentHashes(Uint8List a, Uint8List b) {
  final length = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < length; i++) {
    final diff = a[i] - b[i];
    if (diff != 0) {
      return diff;
    }
  }
  return a.length - b.length;
}
