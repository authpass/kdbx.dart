import 'dart:io';
import 'dart:typed_data';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

/// An [Argon2] which blows up if anybody tries to derive a key with it.
///
/// Used to prove that opening a file with [TransformedKeyCredentials] never
/// reaches the key derivation function — that is the whole point of the api,
/// since Argon2 at usual settings does not fit in an iOS autofill extension.
class _ExplodingArgon2 extends Argon2 {
  const _ExplodingArgon2();

  @override
  bool get isFfi => false;

  @override
  bool get isImplemented => true;

  @override
  Uint8List argon2(Argon2Arguments args) =>
      throw StateError('argon2 must not be called');

  @override
  Future<Uint8List> argon2Async(Argon2Arguments args) =>
      throw StateError('argon2 must not be called');
}

void main() {
  TestUtil.setupLogging();

  final kdbxFormat = KdbxFormat();
  final noArgon2Format = KdbxFormat(const _ExplodingArgon2());

  Future<KdbxFile> readKeeweb([Credentials? credentials]) async {
    final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
    return await kdbxFormat.read(
      data,
      credentials ?? Credentials(ProtectedValue.fromString('asdf')),
    );
  }

  group('exporting', () {
    test('is available after reading a kdbx4 file', () async {
      final file = await readKeeweb();
      final exported = file.transformedKeyCredentials;
      expect(exported, isNotNull);
      expect(exported!.transformedKey, hasLength(32));
      expect(exported.kdfFingerprint, file.kdfFingerprint);
    });

    test('is available after saving', () async {
      final file = TestUtil().createEmptyFile();
      expect(file.transformedKeyCredentials, isNull);
      await file.save();
      expect(file.transformedKeyCredentials, isNotNull);
    });

    test('rotates on every save, because the kdf salt does', () async {
      final file = TestUtil().createEmptyFile();
      await file.save();
      final first = file.transformedKeyCredentials!;
      await file.save();
      final second = file.transformedKeyCredentials!;

      expect(second.kdfFingerprint, isNot(first.kdfFingerprint));
      expect(second.transformedKey, isNot(first.transformedKey));
    });

    test('is dropped when the credentials change', () async {
      final file = await readKeeweb();
      expect(file.transformedKeyCredentials, isNotNull);
      file.credentials = Credentials(ProtectedValue.fromString('other'));
      expect(file.transformedKeyCredentials, isNull);
    });
  });

  group('injecting', () {
    test('opens the file without running argon2', () async {
      final file = await readKeeweb();
      final exported = file.transformedKeyCredentials!;

      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      final reopened = await noArgon2Format.read(data, exported);

      final entry = reopened.body.rootGroup.entries.first;
      expect(entry.getString(KdbxKeyCommon.PASSWORD)!.getText(), 'def');
    });

    test('derives the same keys as the password would', () async {
      final file = await readKeeweb();
      final exported = file.transformedKeyCredentials!;

      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      final reopened = await noArgon2Format.read(data, exported);

      expect(
        reopened.transformedKeyCredentials!.transformedKey,
        exported.transformedKey,
      );
    });

    test('rejects a key that does not match the file', () async {
      final file = await readKeeweb();
      final wrongKey = TransformedKeyCredentials(
        transformedKey: Uint8List(32),
        kdfFingerprint: file.kdfFingerprint,
      );

      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      await expectLater(
        noArgon2Format.read(data, wrongKey),
        throwsA(isA<KdbxInvalidKeyException>()),
      );
    });

    test('rejects a key of the wrong length', () {
      // A long key would otherwise derive the wrong cipher key and report
      // itself as a wrong password, several layers away from the mistake.
      for (final length in [0, 16, 31, 33, 64]) {
        expect(
          () => TransformedKeyCredentials(
            transformedKey: Uint8List(length),
            kdfFingerprint: 'whatever',
          ),
          throwsA(isA<ArgumentError>()),
          reason: 'length $length',
        );
      }
    });

    test('rejects a key derived for different kdf parameters', () async {
      final file = await readKeeweb();
      final stale = TransformedKeyCredentials(
        transformedKey: file.transformedKeyCredentials!.transformedKey,
        kdfFingerprint: 'not-the-fingerprint-of-this-file',
      );

      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      await expectLater(
        noArgon2Format.read(data, stale),
        throwsA(isA<KdbxTransformedKeyStaleException>()),
      );
    });

    test('goes stale once the file is saved again', () async {
      final file = TestUtil().createEmptyFile();
      final bytes = await file.save();
      final exported = file.transformedKeyCredentials!;

      // the key still opens the revision it was exported for.
      await noArgon2Format.read(bytes, exported);

      // ... but not the next one.
      final resaved = await file.save();
      await expectLater(
        noArgon2Format.read(resaved, exported),
        throwsA(isA<KdbxTransformedKeyStaleException>()),
      );
    });

    test('cannot be used to save', () async {
      final data = await File('test/kdbx4_keeweb.kdbx').readAsBytes();
      final file = await readKeeweb();
      final reopened = await noArgon2Format.read(
        data,
        file.transformedKeyCredentials!,
      );

      await expectLater(
        reopened.save(),
        throwsA(isA<KdbxUnsupportedException>()),
      );
    });
  });

  group('kdfFingerprint', () {
    test('is stable for the same file', () async {
      final first = await readKeeweb();
      final second = await readKeeweb();
      expect(second.kdfFingerprint, first.kdfFingerprint);
    });

    test('differs between files', () async {
      final keeweb = await readKeeweb();
      final other = await kdbxFormat.read(
        await File('test/keepassxcpasswords.kdbx').readAsBytes(),
        Credentials(ProtectedValue.fromString('asdf')),
      );
      expect(other.kdfFingerprint, isNot(keeweb.kdfFingerprint));
    });
  });
}
