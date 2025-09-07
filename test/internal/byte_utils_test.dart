import 'dart:typed_data';

import 'package:kdbx/src/utils/byte_utils.dart';
import 'package:test/test.dart';

void main() {
  group('WriteHelper', () {
    test('writing bytes', () {
      final bytesBuilder = BytesBuilder();
      final writer = WriterHelper(bytesBuilder);
      writer.writeUint32(1);
      print('result: ${ByteUtils.toHexList(writer.output.toBytes())}');
      expect(writer.output.toBytes(), hasLength(4));
    });
    test('uint64', () {
      final bytes = WriterHelper.singleUint64Bytes(6000);
      final read = ReaderHelper.singleUint64(bytes);
      print('read: $read');
      expect(read, 6000);
      print('bytes: ${ByteUtils.toHexList(bytes)}');
    });
  });
}
