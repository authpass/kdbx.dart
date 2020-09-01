import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import '../internal/test_utils.dart';
import 'package:logging/logging.dart';

final _logger = Logger('kdbx_merge_test');

void main() {
  TestUtil.setupLogging();
  DateTime now = DateTime.fromMillisecondsSinceEpoch(0);

  final fakeClock = Clock(() => now);
  final kdbxFormat = TestUtil.kdbxFormat();
  void proceedSeconds(int seconds) {
    now = now.add(Duration(seconds: seconds));
  }

  setUp(() {
    DateTime.fromMillisecondsSinceEpoch(0);
  });
  group('Simple merges', () {
    test('Noop merge', () async {
      final file = kdbxFormat.create(
          Credentials.composite(ProtectedValue.fromString('asdf'), null),
          'example');
      _createEntry(file, file.body.rootGroup, 'test1', 'test1');
      final file2 = await TestUtil.saveAndRead(file);
      final merge = file.merge(file2);
      final set = Set<KdbxUuid>.from(merge.merged.keys);
      expect(set, hasLength(2));
      expect(merge.changes, isEmpty);
    });
    test('Username change', () async {
      await withClock(fakeClock, () async {
        final file = kdbxFormat.create(
            Credentials.composite(ProtectedValue.fromString('asdf'), null),
            'example');
        _createEntry(file, file.body.rootGroup, 'test1', 'test1');

        final fileMod = await TestUtil.saveAndRead(file);
        proceedSeconds(10);

        fileMod.body.rootGroup.entries.first
            .setString(KdbxKey('UserName'), PlainValue('changed.'));
        _logger.info('mod date: ' +
            fileMod.body.rootGroup.entries.first.times.lastModificationTime
                .get()
                .toString());
        final file2 = await TestUtil.saveAndRead(fileMod);

        _logger.info('\n\n\nstarting merge.\n');
        final merge = file.merge(file2);
        final set = Set<KdbxUuid>.from(merge.merged.keys);
        expect(set, hasLength(2));
        expect(merge.changes, hasLength(1));
      });
    });
  });
}

KdbxEntry _createEntry(
    KdbxFile file, KdbxGroup group, String username, String password) {
  final entry = KdbxEntry.create(file, group);
  group.addEntry(entry);
  entry.setString(KdbxKey('UserName'), PlainValue(username));
  entry.setString(KdbxKey('Password'), ProtectedValue.fromString(password));
  return entry;
}
