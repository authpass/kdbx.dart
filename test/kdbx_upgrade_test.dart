import 'package:kdbx/src/kdbx_header.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

void main() {
  PrintAppender.setupLogging();
  group('Test upgrade from v3 to v4', () {
    final format = TestUtil.kdbxFormat();
    test('Read v3, write v4', () async {
      final file =
          await TestUtil.readKdbxFile('test/FooBar.kdbx', password: 'FooBar');
      expect(file.header.version, KdbxVersion.V3_1);
      file.upgrade(KdbxVersion.V4.major);
      final v4 = await TestUtil.saveAndRead(file);
      expect(v4.header.version, KdbxVersion.V4);
      await TestUtil.saveTestOutput('kdbx4upgrade', v4);
    });
  });
}
