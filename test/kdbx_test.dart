import 'dart:io';

import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_header.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

void main() {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen(PrintAppender().logListener());
  group('A group of tests', () {
    Awesome awesome;

    setUp(() {
      awesome = Awesome();
    });

    test('First Test', () async {
      final data = await File('test/FooBar.kdbx').readAsBytes();
      await KdbxFormat.read(data, Credentials(ProtectedValue.fromString('FooBar')));
      expect(awesome.isAwesome, isTrue);
    });
  });
}
