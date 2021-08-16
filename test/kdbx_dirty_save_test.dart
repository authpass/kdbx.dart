import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

void main() {
  final testUtil = TestUtil();
  group('test save with dirty objects', () {
    test('modify object after save', () async {
      final file = testUtil.createEmptyFile();
      final group = file.body.rootGroup;
      final entry = testUtil.createEntry(file, group, 'user', 'pass');
      final entry2 = testUtil.createEntry(file, group, 'user', 'pass');
      await file.save();

      const value1 = 'new';
      const value2 = 'new2';
      entry.setString(TestUtil.keyTitle, PlainValue(value1));
      entry2.setString(TestUtil.keyTitle, PlainValue(value1));
      expect(file.isDirty, isTrue);

      await file.save((bytes) async {
        // must still be dirty as long as we are not finished saving.
        expect(file.isDirty, isTrue);
        expect(entry.isDirty, isTrue);
        expect(entry2.isDirty, isTrue);
        return 1;
      });
      expect(file.isDirty, isFalse);
      expect(entry.isDirty, isFalse);
      expect(entry2.isDirty, isFalse);
    });
    test('parallel modify', () async {
      final file = testUtil.createEmptyFile();
      final group = file.body.rootGroup;
      final entry = testUtil.createEntry(file, group, 'user', 'pass');
      final entry2 = testUtil.createEntry(file, group, 'user', 'pass');
      await file.save();

      const value1 = 'new';
      const value2 = 'new2';

      entry.setString(TestUtil.keyTitle, PlainValue(value2));
      entry2.setString(TestUtil.keyTitle, PlainValue(value2));
      await file.save((bytes) async {
        // must still be dirty as long as we are not finished saving.
        expect(file.isDirty, isTrue);
        expect(entry.isDirty, isTrue);
        expect(entry2.isDirty, isTrue);
        entry2.setString(TestUtil.keyTitle, PlainValue(value1));
        return 1;
      });
      expect(file.isDirty, isTrue);
      expect(entry.isDirty, isFalse);
      expect(entry2.isDirty, isTrue);
    });
  });
}
