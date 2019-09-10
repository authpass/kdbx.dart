import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

class ByteUtils {
  static final _random = Random.secure();

  static Uint8List randomBytes(int length) =>
      Uint8List.fromList(List.generate(length, (i) => _random.nextInt(1 << 8)));

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

  static String toHexList(List<int> list) =>
      list?.map((val) => toHex(val))?.join(' ') ?? '(null)';
}

class ReaderHelper {
  ReaderHelper(this.byteData) : lengthInBytes = byteData.lengthInBytes;

  final Uint8List byteData;
  int pos = 0;
  final int lengthInBytes;

//  ByteData _nextByteBuffer(int byteCount) {
//    final ret = ByteData.view(data, pos, pos += byteCount);
//    pos += byteCount;
//    return ret;
//  }

//  ByteData _nextByteBuffer(int byteCount) =>
//      ByteData.view(data, pos, (pos += byteCount) - pos);

//  ByteData _nextByteBuffer(int byteCount) {
//    try {
//      return ByteData.view(data, pos, byteCount);
//    } finally {
//      pos += byteCount;
//    }
//  }

  ByteData _nextByteBuffer(int byteCount) => _advanceByteCount(
      byteCount,
      () => ByteData.view(
          byteData.buffer, pos + byteData.offsetInBytes, byteCount));

  Uint8List _nextBytes(int byteCount) => _advanceByteCount(
      byteCount,
      () => Uint8List.view(
          byteData.buffer, pos + byteData.offsetInBytes, byteCount));

  T _advanceByteCount<T>(int byteCount, T Function() func) {
    try {
      return func();
    } finally {
      pos += byteCount;
    }
  }

  int readUint8() => _nextByteBuffer(1).getUint8(0);
  int readUint16() => _nextByteBuffer(2).getUint16(0, Endian.little);
  int readUint32() => _nextByteBuffer(4).getUint32(0, Endian.little);
  int readUint64() => _nextByteBuffer(8).getUint64(0, Endian.little);

  Uint8List readBytes(int size) => _nextBytes(size);

  Uint8List readBytesUpTo(int maxSize) =>
      _nextBytes(min(maxSize, lengthInBytes - pos));

  Uint8List readRemaining() => _nextBytes(lengthInBytes - pos);

  static int singleUint32(Uint8List bytes) => ReaderHelper(bytes).readUint32();
  static int singleUint64(Uint8List bytes) => ReaderHelper(bytes).readUint64();
}

class WriterHelper {
  WriterHelper([BytesBuilder output]) : output = output ?? BytesBuilder();

  final BytesBuilder output;

  void _write(ByteData byteData) => output.add(byteData.buffer.asUint8List());

  void writeBytes(Uint8List bytes) {
    output.add(bytes);
//    output.asUint8List().addAll(bytes);
  }

  void writeUint32(int value) {
    _write(ByteData(4)..setUint32(0, value, Endian.little));
//    output.asUint32List().add(value);
  }

  void writeUint64(int value) {
    _write(ByteData(8)..setUint64(0, value, Endian.little));
  }

  void writeUint16(int value) {
    _write(ByteData(2)..setUint16(0, value, Endian.little));
  }

  void writeUint8(int value) {
    output.addByte(value);
  }

  static Uint8List singleUint32Bytes(int val) =>
      (WriterHelper()..writeUint32(val)).output.toBytes();
  static Uint8List singleUint64Bytes(int val) =>
      (WriterHelper()..writeUint64(val)).output.toBytes();
}
