@Tags(['kdbx3', 'kdbx4'])

import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

void main() {
  final testUtil = TestUtil();
  group('Test upgrade from v3 to v4', () {
    final format = testUtil.kdbxFormat;
    test('Read v3, write v4', () async {
      final file =
          await testUtil.readKdbxFile('test/FooBar.kdbx', password: 'FooBar');
      expect(file.header.version, KdbxVersion.V3_1);
      file.upgrade(KdbxVersion.V4.major);
      final v4 = await testUtil.saveAndRead(file);
      expect(v4.header.version, KdbxVersion.V4);
      await testUtil.saveTestOutput('kdbx4upgrade', v4);
    }, tags: 'kdbx3');
    test('kdbx4 is the new default', () async {
      final file =
          format.create(Credentials(ProtectedValue.fromString('asdf')), 'test');
      expect(file.header.version, KdbxVersion.V4);
    });
  }, tags: ['kdbx4']);
}
