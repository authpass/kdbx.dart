import 'dart:async';

import 'package:kdbx/kdbx.dart';
import 'package:quiver/core.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

class StreamExpect<T> {
  StreamExpect(this.stream) {
    stream.listen((event) {
      if (_expectNext == null) {
        fail('Got event, but none was expected. $event');
      }
      expect(event, _expectNext!.orNull);
      _expectNext = null;
    }, onDone: () {
      expect(_expectNext, isNull);
      isDone = true;
    }, onError: (dynamic error) {
      expect(_expectNext, isNull);
      this.error = error;
    });
  }

  Future<RET> expectNext<RET>(T value, FutureOr<RET> Function() cb) async {
    if (_expectNext != null) {
      fail('The last event was never received. last: $_expectNext');
    }
    _expectNext = Optional.fromNullable(value);
    try {
      return await cb()!;
    } finally {
      await pumpEventQueue();
    }
  }

  void expectFinished() {
    expect(isDone, true);
  }

  final Stream<T> stream;
  bool isDone = false;
  dynamic error;
  Optional<T>? _expectNext;
}

void main() {
  final testUtil = TestUtil();
  group('test history for values', () {
    test('check history creation', () async {
      final file = await testUtil.readKdbxFile('test/keepass2test.kdbx');
      const valueOrig = 'Sample Entry';
      const value1 = 'new';
      const value2 = 'new2';
      final dirtyExpect = StreamExpect(file.dirtyObjectsChanged);
      {
        final first = file.body.rootGroup.entries.first;
        expect(file.header.version.major, 3);
        expect(first.getString(TestUtil.keyTitle)!.getText(), valueOrig);
        await dirtyExpect.expectNext({first}, () async {
          first.setString(TestUtil.keyTitle, PlainValue(value1));
        });
      }
      expect(file.dirtyObjects, hasLength(1));
      final f2 = await dirtyExpect
          .expectNext({}, () async => testUtil.saveAndRead(file));
      expect(file.dirtyObjects, isEmpty);
      {
        final first = f2.body.rootGroup.entries.first;
        expect(first.getString(TestUtil.keyTitle)!.getText(), value1);
        expect(first.history.last.getString(TestUtil.keyTitle)!.getText(),
            valueOrig);
        await dirtyExpect.expectNext({}, () async => file.save());
      }

      // edit the original file again, and there should be a second history
      {
        final first = file.body.rootGroup.entries.first;
        await dirtyExpect.expectNext({first},
            () async => first.setString(TestUtil.keyTitle, PlainValue(value2)));
      }
      final f3 = await dirtyExpect
          .expectNext({}, () async => testUtil.saveAndRead(file));
      expect(file.dirtyObjects, isEmpty);
      {
        final first = f3.body.rootGroup.entries.first;
        expect(first.getString(TestUtil.keyTitle)!.getText(), value2);
        expect(first.history, hasLength(2));
        expect(
            first.history.last.getString(TestUtil.keyTitle)!.getText(), value1);
        expect(first.history.first.getString(TestUtil.keyTitle)!.getText(),
            valueOrig);
        await dirtyExpect.expectNext({}, () async => file.save());
      }
      file.dispose();
      await pumpEventQueue();
      dirtyExpect.expectFinished();
    });
  }, tags: ['kdbx3']);
}
