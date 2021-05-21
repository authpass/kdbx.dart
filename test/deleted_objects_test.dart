@Tags(['kdbx4'])

import 'package:logging/logging.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

final _logger = Logger('deleted_objects_test');

void main() {
  TestUtil.setupLogging();
  _logger.finest('Running deleted objects tests.');
  group('read tombstones', () {
    test('load/save keeps deleted objects.', () async {
      final orig =
          await TestUtil.readKdbxFile('test/test_files/tombstonetest.kdbx');
      expect(orig.body.deletedObjects, hasLength(1));
      final dt = orig.body.deletedObjects.first.deletionTime.get()!;
      expect([dt.year, dt.month, dt.day], [2020, 8, 30]);
      final reload = await TestUtil.saveAndRead(orig);
      expect(reload.body.deletedObjects, hasLength(1));
    });
  });
}
