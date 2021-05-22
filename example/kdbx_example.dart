import 'package:kdbx/kdbx.dart';

void main() {
  final kdbx = KdbxFormat()
      .create(Credentials(ProtectedValue.fromString('Lorem Ipsum')), 'Example');

  final group = kdbx.body.rootGroup;
  final entry = KdbxEntry.create(kdbx, group);
  group.addEntry(entry);
  entry.setString(KdbxKeyCommon.USER_NAME, PlainValue('example user'));
  entry.setString(
      KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('password'));
  kdbx.save();
}
