import 'dart:typed_data';

import 'package:kdbx/src/credentials/keyfile.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/internal/extension_utils.dart';

abstract class CredentialsPart {
  Uint8List getBinary();
}

abstract class Credentials {
  factory Credentials(ProtectedValue password) =>
      Credentials.composite(password, null); //PasswordCredentials(password);
  factory Credentials.composite(ProtectedValue? password, Uint8List? keyFile) =>
      KeyFileComposite(
        password: password?.let((that) => PasswordCredentials(that)),
        keyFile: keyFile == null ? null : KeyFileCredentials(keyFile),
      );

  factory Credentials.fromHash(Uint8List hash) => HashCredentials(hash);

  Uint8List getHash();
}

class PasswordCredentials implements CredentialsPart {
  PasswordCredentials(this._password);

  final ProtectedValue _password;

  @override
  Uint8List getBinary() {
    return _password.hash;
  }
}

class HashCredentials implements Credentials {
  HashCredentials(this.hash);

  final Uint8List hash;

  @override
  Uint8List getHash() => hash;
}
