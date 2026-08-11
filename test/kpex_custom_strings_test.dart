import 'package:clock/clock.dart';
import 'package:kdbx/kdbx.dart';
import 'package:test/test.dart';

import 'internal/test_utils.dart';

/// Attribute names KeePassXC uses to store passkeys, mirrored by Strongbox,
/// KeePassium and KeePassDX. There is no spec — they are ordinary custom
/// strings, and every implementation is expected to leave the ones it does not
/// understand alone.
///
/// AuthPass does not read these yet, so what matters here is that editing and
/// merging a database never drops them: users share vaults with the apps that
/// do.
final _relyingParty = KdbxKey('KPEX_PASSKEY_RELYING_PARTY');
final _username = KdbxKey('KPEX_PASSKEY_USERNAME');
final _credentialId = KdbxKey('KPEX_PASSKEY_CREDENTIAL_ID');
final _privateKeyPem = KdbxKey('KPEX_PASSKEY_PRIVATE_KEY_PEM');
final _userHandle = KdbxKey('KPEX_PASSKEY_USER_HANDLE');

const _pem = '-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----';

void main() {
  TestUtil.setupLogging();
  final testUtil = TestUtil();

  var now = DateTime.fromMillisecondsSinceEpoch(0);
  final fakeClock = Clock(() => now);
  void proceedSeconds(int seconds) {
    now = now.add(Duration(seconds: seconds));
  }

  setUp(() {
    now = DateTime.fromMillisecondsSinceEpoch(0);
  });

  /// Adds a full set of passkey attributes, protected ones as
  /// [ProtectedValue] the way KeePassXC writes them.
  void addPasskey(KdbxEntry entry) {
    entry.setString(_relyingParty, PlainValue('example.com'));
    entry.setString(_username, PlainValue('alice@example.com'));
    entry.setString(_credentialId, ProtectedValue.fromString('Y3JlZC1pZA'));
    entry.setString(_privateKeyPem, ProtectedValue.fromString(_pem));
    entry.setString(_userHandle, ProtectedValue.fromString('dXNlci1oYW5kbGU'));
  }

  void expectPasskey(KdbxEntry entry) {
    expect(entry.getString(_relyingParty)!.getText(), 'example.com');
    expect(entry.getString(_username)!.getText(), 'alice@example.com');
    expect(entry.getString(_credentialId)!.getText(), 'Y3JlZC1pZA');
    expect(entry.getString(_privateKeyPem)!.getText(), _pem);
    expect(entry.getString(_userHandle)!.getText(), 'dXNlci1oYW5kbGU');
  }

  Future<KdbxFile> createFileWithPasskey() async {
    final file = testUtil.createEmptyFile();
    final entry = testUtil.createEntry(
      file,
      file.body.rootGroup,
      'alice',
      'secret',
    );
    addPasskey(entry);
    return await testUtil.saveAndRead(file);
  }

  group('round trip', () {
    test('survives save and read', () async {
      final file = await createFileWithPasskey();
      expectPasskey(file.body.rootGroup.entries.first);
    });

    test('keeps protected attributes protected', () async {
      final file = await createFileWithPasskey();
      final entry = file.body.rootGroup.entries.first;

      expect(entry.getString(_credentialId), isA<ProtectedValue>());
      expect(entry.getString(_privateKeyPem), isA<ProtectedValue>());
      expect(entry.getString(_userHandle), isA<ProtectedValue>());
      expect(entry.getString(_relyingParty), isA<PlainValue>());
      expect(entry.getString(_username), isA<PlainValue>());
    });

    test('survives editing an unrelated field', () async {
      final file = await createFileWithPasskey();
      file.body.rootGroup.entries.first.setString(
        KdbxKeyCommon.USER_NAME,
        PlainValue('bob'),
      );

      final saved = await testUtil.saveAndRead(file);
      final entry = saved.body.rootGroup.entries.first;
      expect(entry.getString(KdbxKeyCommon.USER_NAME)!.getText(), 'bob');
      expectPasskey(entry);
    });

    test('survives in history entries', () async {
      final file = await createFileWithPasskey();
      file.body.rootGroup.entries.first.setString(
        KdbxKeyCommon.USER_NAME,
        PlainValue('bob'),
      );

      final saved = await testUtil.saveAndRead(file);
      final entry = saved.body.rootGroup.entries.first;
      expect(entry.history, hasLength(1));
      expectPasskey(entry.history.first);
    });
  });

  group('merge', () {
    test('imports attributes added remotely', () async {
      await withClock(fakeClock, () async {
        final file = testUtil.createEmptyFile();
        testUtil.createEntry(file, file.body.rootGroup, 'alice', 'secret');
        proceedSeconds(10);
        final local = await testUtil.saveAndRead(file);

        final remote = await testUtil.saveAndRead(local);
        proceedSeconds(10);
        addPasskey(remote.body.rootGroup.entries.first);
        final remoteSaved = await testUtil.saveAndRead(remote);

        local.merge(remoteSaved);
        expectPasskey(local.body.rootGroup.entries.first);
      });
    });

    test(
      'keeps local attributes when the remote changed another field',
      () async {
        await withClock(fakeClock, () async {
          final file = await createFileWithPasskey();
          proceedSeconds(10);

          final remote = await testUtil.saveAndRead(file);
          proceedSeconds(10);
          remote.body.rootGroup.entries.first.setString(
            KdbxKeyCommon.URL,
            PlainValue('https://example.com'),
          );
          final remoteSaved = await testUtil.saveAndRead(remote);

          file.merge(remoteSaved);
          final entry = file.body.rootGroup.entries.first;
          expect(
            entry.getString(KdbxKeyCommon.URL)!.getText(),
            'https://example.com',
          );
          expectPasskey(entry);
        });
      },
    );

    test(
      'survives a merge into a file which never saw the attributes',
      () async {
        await withClock(fakeClock, () async {
          final file = testUtil.createEmptyFile();
          testUtil.createEntry(file, file.body.rootGroup, 'alice', 'secret');
          proceedSeconds(10);
          final local = await testUtil.saveAndRead(file);

          final remote = await testUtil.saveAndRead(local);
          proceedSeconds(10);
          addPasskey(remote.body.rootGroup.entries.first);
          final remoteSaved = await testUtil.saveAndRead(remote);

          local.merge(remoteSaved);
          // and make sure they make it back out to disk.
          final merged = await testUtil.saveAndRead(local);
          expectPasskey(merged.body.rootGroup.entries.first);
        });
      },
    );
  });
}
