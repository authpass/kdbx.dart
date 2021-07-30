import 'package:test/test.dart';

import '../internal/test_utils.dart';

void main() {
  final testUtil = TestUtil();
  test('load custom icons from file', () async {
    final file = await testUtil.readKdbxFile('test/icon/icontest.kdbx');
    final entry = file.body.rootGroup.entries.first;
    expect(entry.customIcon!.data, isNotNull);
  });
}
