import 'dart:typed_data';

class ByteUtils {
  static bool eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      return false;
    }
    for (int i = a.length - 1; i >= 0; i--) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  static String toHex(int val) => '0x${val.toRadixString(16)}';

  static String toHexList(Uint8List list) => list.map((val) => toHex(val)).join(' ');
}
