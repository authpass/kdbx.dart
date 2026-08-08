class KdbxException implements Exception {}

class KdbxInvalidKeyException implements KdbxException {}

/// Thrown when a [TransformedKeyCredentials] is used against a file whose KDF
/// parameters have changed since the key was derived — i.e. the file was saved
/// in the meantime and [KdbxHeader.generateSalts] rotated the salt.
///
/// This is not a wrong-credentials error: the user's master password is still
/// correct, the cached derived key simply expired and has to be re-derived from
/// the password.
class KdbxTransformedKeyStaleException implements KdbxException {
  KdbxTransformedKeyStaleException({
    required this.expected,
    required this.actual,
  });

  /// Fingerprint the transformed key was derived for.
  final String expected;

  /// Fingerprint of the file being opened.
  final String actual;

  @override
  String toString() {
    return 'KdbxTransformedKeyStaleException{expected: $expected, '
        'actual: $actual}';
  }
}

class KdbxCorruptedFileException implements KdbxException {
  KdbxCorruptedFileException([this.message]);

  final String? message;

  @override
  String toString() {
    return 'KdbxCorruptedFileException{message: $message}';
  }
}

class KdbxUnsupportedException implements KdbxException {
  KdbxUnsupportedException(this.hint);

  final String hint;

  @override
  String toString() {
    return 'KdbxUnsupportedException{hint: $hint}';
  }
}

class KdbxInvalidFileStructure implements KdbxException {
  KdbxInvalidFileStructure(this.message);

  final String message;

  @override
  String toString() {
    return 'KdbxInvalidFileStructure{$message}';
  }
}
