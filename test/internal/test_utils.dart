//typedef HashStuff = Pointer<Utf8> Function(Pointer<Utf8> str);
import 'dart:io';
import 'dart:typed_data';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:kdbx/kdbx.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';

final _logger = Logger('test_utils');

class TestUtil {
  factory TestUtil() => instance;
  TestUtil._() {
    setupLogging();
  }

  static late final instance = TestUtil._();

  static final keyTitle = KdbxKey('Title');

  static void setupLogging() =>
      PrintAppender.setupLogging(stderrLevel: Level.WARNING);

  late final kdbxFormat = _kdbxFormat();

  static KdbxFormat _kdbxFormat() {
    Argon2.resolveLibraryForceDynamic = true;
    return KdbxFormat(Argon2FfiFlutter(resolveLibrary: (path) {
      final cwd = Directory('.').absolute.uri;
      final p = cwd.resolve(path);
      final filePath = p.toFilePath();
      _logger.fine('Resolving $path to: $filePath (${Platform.script})');
      return filePath;
    }));
  }

  Future<KdbxFile> readKdbxFile(
    String filePath, {
    String password = 'asdf',
  }) async {
    final data = await File(filePath).readAsBytes();
    final file = await kdbxFormat.read(
        data, Credentials(ProtectedValue.fromString(password)));
    return file;
  }

  Future<KdbxFile> readKdbxFileBytes(Uint8List data,
      {String password = 'asdf', Credentials? credentials}) async {
    final file = await kdbxFormat.read(
        data, credentials ?? Credentials(ProtectedValue.fromString(password)));
    return file;
  }

  Future<KdbxFile> saveAndRead(KdbxFile file) async {
    return await readKdbxFileBytes(await file.save(),
        credentials: file.credentials);
  }

  Future<void> saveTestOutput(String name, KdbxFile file) async {
    final bytes = await file.save();
    final outFile = File('test_output_$name.kdbx');
    await outFile.writeAsBytes(bytes);
    _logger.info('Written to $outFile');
  }

  KdbxFile createEmptyFile() {
    final file = kdbxFormat.create(
        Credentials.composite(ProtectedValue.fromString('asdf'), null),
        'example');

    return file;
  }

  KdbxEntry createEntry(
    KdbxFile file,
    KdbxGroup group,
    String username,
    String password,
  ) {
    final entry = KdbxEntry.create(file, group);
    group.addEntry(entry);
    entry.setString(KdbxKeyCommon.USER_NAME, PlainValue(username));
    entry.setString(
        KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(password));
    return entry;
  }
}
