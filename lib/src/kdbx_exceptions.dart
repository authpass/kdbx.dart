import 'package:kdbx/src/kdbx_object.dart';

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

/// Thrown when an operation would put two live objects carrying the same uuid
/// into one group - something no kdbx file may contain.
///
/// A file can nevertheless already be in that state: the merge bug fixed after
/// 2.5.0 produced such files, and release builds (with the former assertion
/// compiled out) saved them. See [KdbxFile.duplicateUuidsOnOpen] for detecting
/// that on read and [KdbxDao.mergeDuplicateUuidEntries] for repairing it; a
/// caller which catches this is most likely looking at that residue.
class KdbxDuplicateUuidException implements KdbxException {
  KdbxDuplicateUuidException({required this.uuid, required this.message});

  /// The uuid which is already in use.
  final KdbxUuid uuid;

  final String message;

  @override
  String toString() {
    return 'KdbxDuplicateUuidException{uuid: $uuid, message: $message}';
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
