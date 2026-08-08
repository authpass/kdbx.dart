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

/// Credentials which carry the key material produced *by* the key derivation
/// function, instead of the input to it.
///
/// Opening or saving a file with these skips the KDF (Argon2 / AES-KDF)
/// entirely. That makes kdbx usable in memory constrained environments — an
/// iOS AutoFill extension is capped at roughly 120 MB, well below what Argon2
/// at common KeePass settings needs.
///
/// The key is only valid for the exact KDF parameters it was derived from.
/// [KdbxHeader.generateSalts] rotates the KDF salt on every save, so a stored
/// transformed key goes stale as soon as the file is written — by this
/// application or by any other. [kdfFingerprint] captures the parameters it
/// belongs to; opening a file whose fingerprint differs throws
/// [KdbxTransformedKeyStaleException] rather than reporting a wrong password.
///
/// Obtain one from [KdbxFile.transformedKeyCredentials] after a regular open
/// or save. Only KDBX4 files are supported.
class TransformedKeyCredentials implements Credentials {
  TransformedKeyCredentials({
    required this.transformedKey,
    required this.kdfFingerprint,
  });

  /// The 32 byte output of the key derivation function.
  final Uint8List transformedKey;

  /// Fingerprint of the KDF parameters [transformedKey] was derived from,
  /// as produced by [KdbxFile.kdfFingerprint].
  final String kdfFingerprint;

  /// Always throws — the composite hash is the KDF *input* and cannot be
  /// recovered from its output. Nothing on the KDBX4 read or write path needs
  /// it once a transformed key is available.
  @override
  Uint8List getHash() => throw UnsupportedError(
    'TransformedKeyCredentials carries a post-KDF key, '
    'the composite hash is not recoverable from it.',
  );
}
