class ByteUtils {
  static bool eq(List<int> a, List<int> b) {
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

  static String toHexList(List<int> list) => list.map((val) => toHex(val)).join(' ');
}
