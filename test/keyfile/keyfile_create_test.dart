import 'dart:typed_data';

import 'package:kdbx/kdbx.dart';
import 'package:logging/logging.dart';
import 'package:quiver/iterables.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

import '../internal/test_utils.dart';

final _logger = Logger('keyfile_create_test');

void main() {
  // ignore: unused_local_variable
  final testUtils = TestUtil.instance;
  final exampleBytes = Uint8List.fromList(
      range(0, 16).expand((element) => [0xca, 0xfe]).toList());
  group('creating keyfile', () {
    test('Create keyfile', () {
      final keyFile = KeyFileCredentials.fromBytes(exampleBytes);
      final output = keyFile.toXmlV2String();
      _logger.info(output);
      expect(output, contains('Hash="4CA06E29"'));
      expect(output, contains('CAFECAFE CAFECAFE'));
    });
    test('hex format', () {
      final toTest = {
        'abcd': 'ABCD',
        'abcdefgh': 'ABCDEFGH',
        'abcdef': 'ABCDEF',
        '1234567812345678': '12345678 12345678',
        '12345678123456': '12345678 123456',
      };
      for (final e in toTest.entries) {
        expect(KeyFileCredentials.hexFormatLikeKeepass(e.key), e.value);
      }
    });
    test('create and load', () {
      final keyFile = KeyFileCredentials.fromBytes(exampleBytes);
      final output = keyFile.toXmlV2();
      final read = KeyFileCredentials(output);
      expect(read.getBinary(), equals(exampleBytes));
    });
  });
}
