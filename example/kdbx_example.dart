import 'package:kdbx/kdbx.dart';

Future<void> main() async {
  final credentials = Credentials(ProtectedValue.fromString('Lorem Ipsum'));
  final kdbx = KdbxFormat().create(credentials, 'Example');

  final group = kdbx.body.rootGroup;
  final entry = KdbxEntry.create(kdbx, group);
  group.addEntry(entry);
  entry.setString(KdbxKeyCommon.USER_NAME, PlainValue('example user'));
  entry.setString(
    KdbxKeyCommon.PASSWORD,
    ProtectedValue.fromString('password'),
  );

  // Awaited: `save()` is asynchronous and hands back the file as bytes, so
  // dropping the future means the write may not have happened.
  final bytes = await kdbx.save();

  final reopened = await KdbxFormat().read(bytes, credentials);
  final user = reopened.body.rootGroup.entries.single
      .getString(KdbxKeyCommon.USER_NAME)
      ?.getText();
  print('Saved ${bytes.length} bytes and read back user: $user');
}
