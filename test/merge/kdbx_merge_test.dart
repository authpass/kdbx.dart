import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';

import '../internal/test_utils.dart';

final _logger = Logger('kdbx_merge_test');

void main() {
  TestUtil.setupLogging();
  var now = DateTime.fromMillisecondsSinceEpoch(0);

  final fakeClock = Clock(() => now);
  void proceedSeconds(int seconds) {
    now = now.add(Duration(seconds: seconds));
  }

  setUp(() {
    DateTime.fromMillisecondsSinceEpoch(0);
  });
  group('Simple merges', () {
    Future<KdbxFile> createSimpleFile() async {
      final file = TestUtil.createEmptyFile();
      _createEntry(file, file.body.rootGroup, 'test1', 'test1');
      final subGroup =
          file.createGroup(parent: file.body.rootGroup, name: 'Sub Group');
      _createEntry(file, subGroup, 'test2', 'test2');
      proceedSeconds(10);
      return await TestUtil.saveAndRead(file);
    }

    test('Noop merge', () async {
      final file = await createSimpleFile();
      final file2 = await TestUtil.saveAndRead(file);
      final merge = file.merge(file2);
      final set = Set<KdbxUuid>.from(merge.merged.keys);
      expect(set, hasLength(4));
      expect(merge.changes, isEmpty);
    });
    test('Username change', () async {
      await withClock(fakeClock, () async {
        final file = await createSimpleFile();

        final fileMod = await TestUtil.saveAndRead(file);

        fileMod.body.rootGroup.entries.first
            .setString(KdbxKey('UserName'), PlainValue('changed.'));
        _logger.info('mod date: ' +
            fileMod.body.rootGroup.entries.first.times.lastModificationTime
                .get()
                .toString());
        final file2 = await TestUtil.saveAndRead(fileMod);

        _logger.info('\n\n\nstarting merge.\n');
        final merge = file.merge(file2);
        expect(file.body.rootGroup.entries.first.history, hasLength(1));
        final set = Set<KdbxUuid>.from(merge.merged.keys);
        expect(set, hasLength(4));
        expect(merge.changes, hasLength(1));
      });
    });
    test(
      'Change Group Name',
      () async => await withClock(fakeClock, () async {
        final file = await createSimpleFile();

        final fileMod = await TestUtil.saveAndRead(file);

        fileMod.body.rootGroup.groups.first.name.set('Sub Group New Name.');
        final file2 = await TestUtil.saveAndRead(fileMod);
        final merge = file.merge(file2);
        final set = Set<KdbxUuid>.from(merge.merged.keys);
        expect(set, hasLength(4));
        expect(merge.changes, hasLength(1));
      }),
    );
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
