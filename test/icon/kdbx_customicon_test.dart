import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

import '../internal/test_utils.dart';

void main() {
  PrintAppender.setupLogging();
  test('load custom icons from file', () async {
    final file = await TestUtil.readKdbxFile('test/icon/icontest.kdbx');
    final entry = file.body.rootGroup.entries.first;
    expect(entry.customIcon.data, isNotNull);
  });
}
