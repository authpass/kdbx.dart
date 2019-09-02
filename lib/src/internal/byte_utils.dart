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
      list.map((val) => toHex(val)).join(' ');
}

class ReaderHelper {
  ReaderHelper(this.data);

  final Uint8List data;
  int pos = 0;

  ByteBuffer _nextByteBuffer(int byteCount) =>
      (data.sublist(pos, pos += byteCount) as Uint8List).buffer;

  int readUint32() => _nextByteBuffer(4).asUint32List().first;

  int readUint16() => _nextByteBuffer(2).asUint16List().first;

  int readUint8() => data[pos++];

  ByteBuffer readBytes(int size) => _nextByteBuffer(size);

  ByteBuffer readBytesUpTo(int maxSize) =>
      _nextByteBuffer(min(maxSize, data.lengthInBytes - pos));

  Uint8List readRemaining() => data.sublist(pos) as Uint8List;
}

class WriterHelper {
  WriterHelper([BytesBuilder output]) : output = output ?? BytesBuilder();

  final BytesBuilder output;

  void writeBytes(Uint8List bytes) {
    output.add(bytes);
//    output.asUint8List().addAll(bytes);
  }

  void writeUint32(int value) {
    output.add(Uint32List.fromList([value]).buffer.asUint8List());
//    output.asUint32List().add(value);
  }

  void writeUint64(int value) {
    output.add(Uint64List.fromList([value]).buffer.asUint8List());
  }

  void writeUint16(int value) {
    output.add(Uint16List.fromList([value]).buffer.asUint8List());
  }

  void writeUint8(int value) {
    output.addByte(value);
  }
}
