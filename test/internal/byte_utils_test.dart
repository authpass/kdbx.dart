
import 'dart:io';

import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:test/test.dart';

void main() {
  group('WriteHelper', () {
    test('writing bytes', () {
      final bytesBuilder = BytesBuilder();
      final writer = WriterHelper(bytesBuilder);
      writer.writeUint32(1);
      print('result: ' + ByteUtils.toHexList(writer.output.toBytes()));
      expect(writer.output.toBytes(), hasLength(4));
    });
  });
}
