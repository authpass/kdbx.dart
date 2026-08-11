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

  /// The composite hash, which is the input to the key derivation function.
  ///
  /// May throw [UnsupportedError]: an implementation is allowed to carry the
  /// KDF *output* instead, and the input cannot be recovered from it. The one
  /// in this package that does is [TransformedKeyCredentials]. Callers that
  /// hash, cache or log credentials generically should be prepared for that,
  /// or check the type first.
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
  }) {
    // Checked here rather than on use. A short key throws a RangeError from
    // inside the key/seed concatenation, and a long one is worse: it derives
    // the wrong cipher key and surfaces as a decryption failure, which reads
    // like a wrong password. The assert on the concatenated length is no help
    // in release builds.
    if (transformedKey.length != _transformedKeyLength) {
      throw ArgumentError.value(
        transformedKey.length,
        'transformedKey',
        'A transformed key is the $_transformedKeyLength byte output of the '
            'key derivation function; got a length of',
      );
    }
  }

  static const _transformedKeyLength = 32;

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
